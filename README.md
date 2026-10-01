# bd — a coordination engine for agents, on SQLite WAL

`bd` is a Rust re-implementation of [beads](https://github.com/gastownhall/beads)
(the `bd` issue tracker for AI coding agents) as a fast, embeddable
coordination engine:

- **Task lifecycle**: `open → in_progress → closed`, plus `blocked`, `deferred`, `pinned`
- **Typed dependency graph**: `blocks`, `conditional-blocks`, `parent-child`, `waits-for` gate readiness; informational edges (`related`, `discovered-from`, …) never do. Cycles and hierarchy deadlocks are rejected at write time.
- **Deterministic ready work**: a materialized blocked flag maintained in the same transaction as every change, and a total queue order (policy, then id)
- **Leased atomic claiming**: claims run under SQLite's write lock and return a lease with a fencing token
- **Crash recovery**: expired leases are reclaimed after a grace window (automatically by `claim --next`); WAL makes every transaction atomic
- **Optimistic concurrency**: per-issue revisions and `--if-revision/--if-status/--if-assignee` guards (exit code 13 on conflict)
- **Comments, durable memory, and transactional event history** with gapless, commit-ordered sequence numbers
- Extras: JSONL export/import (reads beads exports), `bd batch` (many writes, one transaction), `bd bench`, and local observability (structured logs, timing, Prometheus metrics, `bd doctor`)

It ships as a library (`crates/bd-core`) and a CLI (`crates/bd-cli`, binary `bd`).

## How beads works (and what this keeps)

Beads stores issues in an embedded Dolt (versioned SQL) database under
`.beads/`, syncs it across machines with `bd dolt push/pull`, and gives agents
a dependency-aware work queue:

| beads concept | beads implementation | here |
|---|---|---|
| Issues | `issues` table; hash ids `prefix-<base36>` with adaptive length; child ids `parent.N` | same id scheme (plus `counter` mode) |
| Dependencies | `dependencies(issue_id, depends_on_id, type)`; one edge per pair; cycle check via recursive CTE | same, plus BFS cycle *path* in errors |
| Ready work | materialized `issues.is_blocked`, recomputed per affected set to a fixpoint; ready = `open` ∧ ¬blocked ∧ not deferred | same model; deferral also hides grandchildren (beads checks one level) |
| `conditional-blocks` | documented as "runs only if the blocker fails"; implemented exactly like `blocks` | implemented as documented, using an explicit close outcome (`bd close --failed`) |
| Claims | `UPDATE … WHERE row_lock = ?` compare-and-swap; Dolt merges + retries | `BEGIN IMMEDIATE`: the read-check-write runs under SQLite's single writer lock, so no retries |
| Leases | node-local `leases` table, 5 min TTL, `bd heartbeat`, `bd reclaim` with 2×TTL grace | same, plus a fencing token, and `claim --next` auto-reclaims |
| Concurrency guards | random `row_lock`; `--if-assignee/--if-status` (exit 13) | monotonic `revision` plus the same guards |
| Events | audit `events` table plus an opt-in `bd_events_journal` with gapless seq from a counter row | one always-on log; `AUTOINCREMENT` seq written in the mutation's transaction |
| Memory | `config` rows `kv.memory.<key>`, key derived from content, injected by `bd prime` | dedicated table with authorship, revisions, and CAS |

## Install

```bash
cargo install --path crates/bd-cli      # installs ~/.cargo/bin/bd
```

**Living next to Go beads.** If the Go `bd` is also installed, rename it to
`beads` (for example `mv ~/.local/bin/bd ~/.local/bin/beads`). When the
nearest workspace is a Go-beads `.beads/` directory (and not a `.bd/` one),
this `bd` forwards the command line unchanged to `beads`, so existing hooks
(`bd prime`) and repositories keep working. `init`, `version`, `help`, and
`bench` always run natively.

| Variable | Effect |
|---|---|
| `BD_LEGACY_FALLBACK=0` | disable forwarding |
| `BD_LEGACY_BIN=/path/to/beads` | use a specific legacy binary |
| `--db PATH` / `BD_DB` | always native |

## Quick start

```bash
bd init --prefix demo                       # creates .bd/bd.db (WAL)
bd create "Design schema" -p 1
bd create "Implement API" -p 2 --dep demo-xyz   # blocked until demo-xyz closes
bd ready                                    # unblocked work, queue order
bd claim --next                             # atomic claim + 5m lease (prints token)
bd heartbeat demo-xyz --token 42            # renew while working
bd close demo-xyz --reason "merged" --token 42
bd prime                                    # agent context: claims, ready work, memories
```

Agent loop: `bd claim --next --json` → work, heartbeating every few minutes
→ `bd close <id> --token <t>` (or `--failed`). If `heartbeat` exits 4, the
lease was lost (reclaimed or taken over): stop working on that issue.

## Concepts

### Statuses

| status | ready? | releases dependents? | notes |
|---|---|---|---|
| `open` | yes, if not blocked or deferred | no | |
| `in_progress` | no | no | always has an assignee and a lease |
| `blocked` | no | no | manual "stuck" state |
| `deferred` | no | no | parked indefinitely (`bd defer <id>`) |
| `closed` | no | **yes** | outcome `done` or `failed` |
| `pinned` | no | **yes** | persistent context, never work |

`bd defer <id> --until 2026-01-15` keeps the status but hides the issue and
its whole subtree from ready work until then. Closing a parent with open
children, or closing a blocked issue, is refused unless you pass `--force`.

### Dependency types (`bd dep add ISSUE DEPENDS_ON -t TYPE`)

| type | effect on ISSUE |
|---|---|
| `blocks` (default) | blocked while DEPENDS_ON is not closed/pinned |
| `conditional-blocks` | runs only if DEPENDS_ON closes as **failed**; stays blocked if it succeeds |
| `parent-child` | hierarchy (one parent); a blocked parent blocks its whole subtree, never the reverse |
| `waits-for` | fan-in gate on DEPENDS_ON's children: `--gate all-children` (default) or `any-children`; metadata `also_blocks: true` also waits on the spawner itself |
| `related`, `discovered-from`, `tracks`, `caused-by`, `validates`, `supersedes`, `duplicates`, `replies-to`, custom | informational only |

### Ready-work order

`--sort priority` (default): priority, then oldest, then id. `--sort oldest`:
creation time, then id. `--sort hybrid`: issues from the last 48h by
priority, then older ones by age. Every policy ends with `id`, so the same
state and clock always give the same queue. Epics are containers and are
excluded unless you pass `--include-epics` or `-t epic`.

### Claims, leases, and recovery

- `bd claim <id>` succeeds only if the issue is `open`, ready, and unassigned, reserved for you, or held by a `claim.pools` alias. Re-claiming your own claim is idempotent and refreshes the lease.
- `bd claim --next` claims the head of the ready queue inside one write transaction, so two agents can never take the same issue. It first reclaims leases that expired more than `lease.grace` ago.
- The lease `token` is the sequence number of the `claimed` event: unique and increasing. Pass it to `heartbeat`, `close`, or `release` so a stale worker cannot act on a claim it no longer holds.
- `bd reclaim [--grace 10m]` reverts dead workers' issues to `open` and records `reclaimed` events. `bd leases` shows lease health.
- Invariant (checked by `bd doctor`): a lease exists if and only if the issue is `in_progress`, and the lease holder is the assignee.

### Optimistic concurrency

Every issue has a `revision` that increases on each change to the issue
itself. Comments, heartbeats, and derived blocked-flag changes do not bump
it. Read it, decide, then write conditionally:

```bash
rev=$(bd show demo-xyz --json | jq .revision)
bd update demo-xyz --status blocked --if-revision "$rev"   # exit 13 if someone else changed it
bd release demo-xyz --if-assignee worker-7                  # CAS release for supervisors
bd remember --key deploy "use blue/green" --if-revision 0   # create-only memory
```

### Event history

Each mutation appends events in its own transaction, so the log and the state
never disagree. Ops:

- issue lifecycle: `created`, `updated` (field-level old/new), `closed`, `reopened`, `deleted` (with a snapshot)
- claims: `claimed`, `released`, `reclaimed`, `lease_granted`
- graph: `dep_added`, `dep_removed`, `dep_updated`, `blocked`, `unblocked`
- other: `commented`, `memory_set`, `memory_deleted`, `config_set`, `imported`, `pruned`

`seq` is gapless and commit-ordered. `tx` groups the events of one
transaction.

```bash
bd events -n 20                    # recent events
bd events --since 1200 --follow    # tail from a cursor (JSON lines with --json)
bd history demo-xyz                # one issue (survives deletion)
bd events prune --older-than 30d   # retention; a cursor behind it fails (exit 6)
```

To mirror the state elsewhere, `bd export` writes a snapshot whose header
carries `head_seq`. Load it, then tail `--since head_seq`.

### Comments and memory

```bash
bd comment add demo-xyz "API shape agreed with the frontend team"
bd remember "Integration tests need docker running"   # key derived: integration-tests-need-docker-running
bd memories docker ; bd recall <key> ; bd forget <key>
```

`bd prime` prints workflow context, your claims, top ready work, and all
memories. Outside a workspace it prints nothing (safe in session hooks).

## Observability

Everything is local; nothing is sent anywhere.

- **Logs**: `BD_LOG=bd=debug bd …` shows per-transaction lock-wait, exec, and commit timings on stderr. `--log-format json` emits structured logs.
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

## Benchmarks

`bd bench` seeds a random DAG on a scratch database, drains it with N
workers (claim → work → close), and verifies from the event log that every
issue was claimed and closed exactly once and never before its blockers
closed. It has three modes:

- `threads`: an embedded library, one connection per thread
- `processes`: long-lived worker processes
- `cli`: a fresh `bd` process per operation, which is what agents experience

Results on a WSL2 laptop (release build, `durability=normal`, 3,000 issues, about one blocking edge each):

| mode | workers | claims/s | write tx/s | claim p50 | claim p99 |
|---|---|---|---|---|---|
| threads | 1 | 3,600 | 7,100 | 63 µs | 0.2 ms |
| threads | 4 | 4,500 | 9,000 | 87 µs | 10 ms |
| processes | 8 | 4,700 | 9,300 | 85 µs | 11 ms |
| cli | 1 | 235 | 470 | 2.0 ms | 2.6 ms |
| cli | 8 | 920 | 1,800 | 2.7 ms | 22 ms |

SQLite has one writer, so throughput plateaus around the single-writer rate.
Tail latency comes from contention and WAL-checkpoint fsyncs: with
`--durability off`, p99 drops below 0.4 ms. `durability=full` fsyncs every
commit and is bounded by the disk's fsync latency.

## Configuration (`bd config list|get|set|unset`)

| key | default | meaning |
|---|---|---|
| `issue_prefix` | from the directory name | id prefix |
| `id.mode` | `hash` | `hash` or `counter` |
| `lease.ttl` | `5m` | claim lease duration |
| `lease.grace` | `10m` | how long past expiry before reclaim reverts a claim |
| `lease.auto_reclaim` | `true` | `claim --next` reclaims stale leases first |
| `claim.pools` | | comma-separated assignees anyone may claim from |
| `types.custom` | | extra issue types |
| `durability` | `normal` | SQLite `synchronous`: `off`, `normal`, `full` |
| `events.retain_days` / `events.retain_rows` | `0` | automatic event retention (`0` keeps everything) |

The actor comes from `--actor`, then `$BD_ACTOR`, `$BEADS_ACTOR`, `git config user.name`, then `$USER`.

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | internal or doctor problems |
| 2 | invalid input, cycle, or policy refusal |
| 3 | not found or no workspace |
| 4 | claim conflict: already claimed, not ready, not owner, or lease lost |
| 5 | database busy |
| 6 | event cursor truncated |
| 13 | stale optimistic-concurrency guard |

With `--json`, errors are printed to stderr as `{"error":{"code","message","exit_code"}}`.

## Library

```rust
use bd_core::{ClaimOptions, CloseOptions, NewIssue, OpenOptions, Queries, ReadyQuery, Store};

let mut store = Store::open(std::path::Path::new(".bd/bd.db"), OpenOptions::default())?;
let id = store.write("create", "planner", |tx| Ok(tx.create_issue(NewIssue::titled("Index the repo"))?.id))?;
if let Some(claim) = store.write("claim", "agent-1", |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()))? {
    let close = CloseOptions { token: Some(claim.lease.token), ..Default::default() };
    store.write("close", "agent-1", |tx| tx.close_issue(&claim.issue.id, &close))?;
}
let ready = store.read(|r| r.ready(&ReadyQuery::default()))?;
```

`Store::write` runs the closure in one `BEGIN IMMEDIATE` transaction and
records its timing. `Store::read` runs against one consistent snapshot. Open
one `Store` per thread or process; the database file is the coordination
point.

## Layout

```
crates/bd-core/src/   store (WAL, transactions, busy handling) · schema · issues · graph (deps + blocked state)
                      ready · claims (leases) · events · comments · memory · config · transfer (JSONL)
                      metrics · doctor · queries (read API)
crates/bd-core/tests/ engine integration tests (graph semantics, leases with a manual clock, concurrency)
crates/bd-cli/src/    cli (clap) · commands · batch · bench · legacy (forwarding) · fmt · logging
crates/bd-cli/tests/  end-to-end CLI tests
```

Build and test: `cargo build --release && cargo test --workspace`.
