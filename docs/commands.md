# Command reference

Every command takes `--help` for its full options (`bd claim --help`,
`bd serve token --help`). This page groups the commands, then lists the
global options, environment variables, configuration keys and exit codes.

## Commands

| area | commands | see |
|---|---|---|
| Workspace | `init` (create `.bd/bd.db` here), `info`, `config`, `stats`, `doctor`, `version` | [Configuration](#configuration-bd-config-listgetsetunset), [Observability](observability.md) |
| Issues | `create`, `show`, `list`, `update`, `close`, `reopen`, `defer`, `undefer`, `delete`, `label add/rm/list` | [Statuses](concepts.md#statuses) |
| Dependencies | `dep add/rm/list/tree/cycles`, `blocked` | [Dependency types](concepts.md#dependency-types-bd-dep-add-issue-depends_on--t-type) |
| Ready work and claims | `ready`, `claim` (`--next`), `heartbeat`, `release`, `reclaim`, `leases` | [Ready-work order](concepts.md#ready-work-order), [Claims](concepts.md#claims-leases-and-recovery) |
| Comments and memory | `comment add`, `comments`, `memory`, `remember`, `recall`, `memories`, `forget` | [Comments and memory](concepts.md#comments-and-memory) |
| Events | `events` (`--follow`, `--wait`, `prune`), `history` | [Event history](concepts.md#event-history) |
| Agents | `prime`, `hook session-start/subagent-start/pre-tool-use`, `agents status/pull/approve/watch/manifest` | [Actors](concepts.md#actors), [Agent skills](agents.md) |
| Playbooks and gates | `playbook list/show/plan/run/status/runs/compact/discard/extract`, `gate list/show/check/resolve/create`, `purge` | [Playbooks](playbooks.md) |
| Data | `export`, `import` (bd or beads JSONL, all or nothing), `batch` (many writes in one transaction, `--dry-run` rolls back) | [Migrating](beads.md#migrating-from-go-beads) |
| Operations | `metrics`, `bench` | [Observability](observability.md), [Benchmarks](benchmarks.md) |
| Remote | `serve`, `serve token create/list/revoke/accounts`, `remote set/show/unset/login/logout` | [Remote server](remote.md) |

## Global options

| option | env | meaning |
|---|---|---|
| `--db PATH` | `BD_DB` | database file (default: the nearest `.bd/bd.db` walking up from the current directory) |
| `--remote URL` | `BD_REMOTE` | a workspace on a bd server (default: `.bd/remote.toml`) |
| `-C DIR` | | run as if started in `DIR` |
| `--actor NAME` | `BD_ACTOR` | act as this actor ([Actors](concepts.md#actors)) |
| `--session NAME` | `BD_SESSION` | name this session: act as `<user>/<harness session>.<NAME>` |
| `--json` | | machine-readable output; errors go to stderr as `{"error":{"code","message","exit_code"}}` |
| `-q`, `--quiet` | | minimal output (ids only) |
| `--log-format text\|json` | `BD_LOG_FORMAT` | diagnostics format on stderr (filter with `BD_LOG`) |
| `--timing` | `BD_TIMING=1` | per-command timing on stderr |
| `--slow-ms MS` | `BD_SLOW_MS` | warn about operations slower than this (default 250) |
| `--busy-timeout-ms MS` | `BD_BUSY_TIMEOUT_MS` | how long a writer waits for the database write lock, and `bd agents` for a checkout's agent assets mutex (default 10000) |

## Environment variables

Besides the variables of the global options:

| variable | meaning |
|---|---|
| `BEADS_ACTOR` | read after `BD_ACTOR`, for beads compatibility |
| `CLAUDE_CODE_SESSION_ID`, `COPILOT_AGENT_SESSION_ID`, `CODEX_THREAD_ID` (`CODEX_SESSION_ID`) | set by agent harnesses; give each session its own actor ([Actors](concepts.md#actors)) |
| `BD_LOG` | log filter, e.g. `bd=debug` or `bd::serve=debug` ([Observability](observability.md)) |
| `NO_COLOR` | no colors in logs |
| `BD_PLAYBOOK_PATH` | extra playbook directories, colon separated (semicolons on Windows) ([Playbooks](playbooks.md#writing-a-playbook)) |
| `BD_GH` | the `gh` binary GitHub gates run ([Gates](playbooks.md#gates)) |
| `BD_TOKEN`, `BD_CA_CERT`, `BD_REMOTE_RETRY_SECS`, `BD_INSECURE_HTTP` | remote clients ([Clients](remote.md#clients)) |

## Configuration (`bd config list|get|set|unset`)

| key | default | meaning |
|---|---|---|
| `issue_prefix` | from the directory name | id prefix |
| `id.mode` | `hash` | `hash` or `counter` |
| `lease.ttl` | `5m` | claim lease duration |
| `lease.grace` | `10m` | how long past expiry before reclaim reverts a claim; until then it stays live, its holder's |
| `lease.auto_reclaim` | `true` | `claim --next` reclaims stale leases first, and `bd serve` reclaims them every minute |
| `claim.pools` | | comma-separated assignees anyone may claim from |
| `types.custom` | | extra issue types |
| `durability` | `normal` | SQLite `synchronous`: `off`, `normal`, `full` |
| `events.retain_days` / `events.retain_rows` | `0` | automatic event retention (`0` keeps everything) |
| `gate.repos` | | repositories GitHub gates may name: `OWNER/REPO`, `HOST/OWNER/REPO`, `OWNER/*`, `*` (unset: any locally, the workspace's own through `bd serve`) |

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | internal or doctor problems |
| 2 | invalid input (including `--force` on `update`/`release`: use `--take-over`), cycle, or policy refusal |
| 3 | not found or no workspace |
| 4 | claim conflict: already claimed (a live claim, even your own actor's, without its `--token`), not ready, not the holder of a live claim (`--take-over` takes it over; `--force` does not), or lease lost |
| 5 | busy: the database write lock or a checkout's agent assets mutex (`.bd/agents.lock.mutex`) stayed held past `--busy-timeout-ms`, or another bd process kept the access tokens (`tokens.lock`) or saved credentials (`credentials.lock`) locked; retry |
| 6 | event cursor truncated |
| 7 | access denied: missing, invalid or expired token, or its role, kind, workspaces or actor do not allow it; or a GitHub sign-in that was refused |
| 8 | bd server unreachable, its certificate not trusted, or a server failure: the command did not take effect (retrying is safe) |
| 9 | a write reached the bd server, but its answer was lost: it may have taken effect, so check before running it again |
| 13 | stale optimistic-concurrency guard |

With `--json`, errors are printed to stderr as `{"error":{"code","message","exit_code"}}`.
