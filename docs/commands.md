# Command reference

Every command takes `--help` for its full options (`bd claim --help`,
`bd serve token create --help`). This page groups the commands, then lists
the global options, environment variables, configuration keys, exit codes
and error codes.

## Commands

| area | commands | see |
|---|---|---|
| Workspace | `init` (`--prefix`, `--id-mode hash\|counter`), `info`, `config get/set/unset/list`, `stats`, `doctor`, `version` | [Configuration](#configuration), [Observability](observability.md) |
| Issues | `create`, `show`, `list`, `update`, `close`, `reopen`, `defer`, `undefer`, `delete`, `label add/rm/list` | [Issues](concepts.md#issues) |
| Dependencies | `dep add/rm/list/tree/cycles`, `blocked` | [Dependency types](concepts.md#dependency-types) |
| Ready work and claims | `ready`, `claim` (`--next`), `heartbeat` (`hb`), `release` (`unclaim`), `reclaim`, `leases` | [Ready work](concepts.md#ready-work), [Claims](concepts.md#claims-leases-and-recovery) |
| Comments and memory | `comment add/list`, `comments`, `remember`, `recall`, `memories`, `forget`, `memory add/get/list/rm` | [Comments and memory](concepts.md#comments-and-memory) |
| Events | `events` (`--follow`, `--wait`, `prune`), `history` | [Event history](concepts.md#event-history) |
| Agents | `prime`, `hook session-start/subagent-start/pre-tool-use`, `agents manifest/status/pull/approve/watch`, `mcp` | [Agent assets](agents.md), [MCP server](mcp.md) |
| Playbooks and gates | `playbook list/show/plan/run/status/runs/compact/discard/extract`, `gate list/show/check/resolve/create`, `purge` | [Playbooks](playbooks.md) |
| Data | `export`, `import`, `batch`, `backup` | [below](#data) |
| Operations | `metrics`, `bench` | [Observability](observability.md), [Benchmarks](benchmarks.md) |
| Remote | `serve`, `serve check`, `serve token create/list/revoke/events/accounts/link/name`, `remote set/show/unset/login/logout` | [Remote server](remote.md), [Signing in](sign-in.md) |

`rm` subcommands also answer to `remove`, and `list` subcommands of
`playbook`, `gate` and `serve token` to `ls`.

### Issues

```bash
bd create "Title" -d "why and what" -t task -p 2 [-a ASSIGNEE] [-l a,b] [--parent ID] [--dep TYPE:ID]
          [--design T] [--acceptance T] [--notes T] [--estimate MIN] [--due WHEN] [--defer WHEN]
          [--external-ref REF] [--metadata JSON] [--id ID] [--pinned] [--ephemeral] [--claim]
bd update ID [--title T] [-d T] [--status S] [-p N] [-t TYPE] [-a A] [--append-notes T]
          [--add-label L] [--remove-label L] [--set-labels a,b] [--parent ID]
          [--set-metadata K=V] [--unset-metadata K] [--ephemeral BOOL] [--if-revision N] [--take-over] ...
bd list [-s S,S] [--search TEXT] [--all] [--blocked] [--sort priority|created|updated|id] [--reverse] [-n 100] [filters]
bd close ID... -r "reason" [--failed] [--token T] [--force] [--take-over]   # --reason, or --message
bd delete ID... [--cascade] [--force] [--dry-run] [--take-over]
```

Times (`--due`, `--defer`, `--until`) take a date (`2026-01-15`), an
offset (`+2d`) or RFC 3339. Status values accept `wip`/`inprogress` for
`in_progress` and `done` for `closed`.

### Data

- **`bd export [-o FILE]`** writes JSONL: a header with `head_seq`, then
  issues, dependencies, comments and memories. `--no-memories`,
  `--open-only`, `--include-ephemeral`.
- **`bd import FILE`** reads bd or beads JSONL, all or nothing.
  `--dry-run` validates and reports without writing; `--lenient` keeps
  unknown issue types and maps unknown statuses to `open`; `--take-over`
  imports over other actors' live claims.
- **`bd batch [-f FILE]`** (default stdin) runs many writes in one
  transaction: each line is a subcommand with its usual flags (`create`,
  `update`, `close`, `dep add`, …), `$N` stands for the id produced by the
  Nth operation, and `#` starts a comment. Any failure rolls back
  everything; `--dry-run` runs everything, reports, then rolls back.
- **`bd backup --to DIR [--keep 24] [--name NAME]`** writes a verified copy
  of a local workspace's database ([Backing up](modes.md#backing-up-a-local-workspace)).

## Global options

| option | env | meaning |
|---|---|---|
| `--db PATH` | `BD_DB` | database file (default: the nearest `.bd/bd.db` walking up from the current directory) |
| `--remote URL` | `BD_REMOTE` | a workspace on a bd server (default: `.bd/remote.toml`); not with `--db` |
| `-C, --directory DIR` | | run as if started in `DIR` |
| `--actor NAME` | | act as this actor (else `$BD_ACTOR`; [Actors](concepts.md#actors)) |
| `--session NAME` | | name this session, as `$BD_SESSION` does |
| `--json` | | machine-readable output; errors go to stderr as `{"error": {"code", "message", "exit_code"}}` |
| `-q, --quiet` | | minimal output (ids only) |
| `--log-format text\|json` | `BD_LOG_FORMAT` | diagnostics format on stderr (default text; filter with `BD_LOG`) |
| `--timing` | `BD_TIMING=1` | per-command timing on stderr |
| `--slow-ms MS` | `BD_SLOW_MS` | warn about operations slower than this (default 250) |
| `--busy-timeout-ms MS` | `BD_BUSY_TIMEOUT_MS` | how long a writer waits for the database write lock, and `bd agents` for a checkout's mutex (default 10000) |

## Environment variables

Besides those of the global options:

| variable | meaning |
|---|---|
| `BD_ACTOR`, then `BEADS_ACTOR` | the actor ([Actors](concepts.md#actors)) |
| `BD_SESSION` | name this session: act as `<user>/<harness session>.<NAME>` |
| `CLAUDE_CODE_SESSION_ID`, `COPILOT_AGENT_SESSION_ID`, `CODEX_THREAD_ID` (`CODEX_SESSION_ID`) | set by agent harnesses; give each session its own actor |
| `CLAUDE_ENV_FILE`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME` | harness locations read by hooks and `bd agents pull` ([Agent assets](agents.md)) |
| `BD_LOG` | log filter, e.g. `bd=debug` or `bd::serve=debug` ([Observability](observability.md)) |
| `NO_COLOR` | no colors in logs |
| `BD_PLAYBOOK_PATH` | extra playbook directories, `:`-separated (`;` on Windows) |
| `BD_GH` | the `gh` binary GitHub gates run |
| `BD_TOKEN`, `BD_CA_CERT`, `BD_REMOTE_RETRY_SECS`, `BD_INSECURE_HTTP` | remote clients ([Environment](remote.md#environment)) |
| `BD_SERVE_ROOT`, `BD_SERVE_PUBLIC_URL` | `--root` of `bd serve`, `bd serve check` and `bd serve token`; `--public-url` of `bd serve` and `bd serve check` |
| `XDG_CONFIG_HOME`, `APPDATA`, `HOME`, `USERPROFILE` | where saved tokens and user playbooks live |
| `USER`, `USERNAME` | the user, when `git config user.name` is unset |

## Configuration

`bd config list|get|set|unset KEY [VALUE]`. Through `bd serve`, setting
and unsetting need an admin token.

| key | default | meaning |
|---|---|---|
| `issue_prefix` | set by `bd init` (from the directory name) | id prefix; cannot be unset |
| `id.mode` | `hash` | `hash` or `counter` |
| `lease.ttl` | `5m` | claim lease duration (at least 1s) |
| `lease.grace` | `10m` | how long past expiry before a claim is dead and reclaimable |
| `lease.auto_reclaim` | `true` | `claim --next` reclaims dead claims first, and `bd serve` reclaims them every minute |
| `claim.pools` | | comma-separated assignees anyone may claim from |
| `types.custom` | | extra issue types |
| `durability` | `normal` | SQLite `synchronous`: `off`, `normal`, `full` |
| `events.retain_days`, `events.retain_rows` | `0` | automatic event retention (`0` keeps everything) |
| `gate.repos` | | repositories GitHub gates may name: `OWNER/REPO`, `HOST/OWNER/REPO`, `OWNER/*`, `HOST/OWNER/*`, `*` (unset: any locally, only the workspace's own through `bd serve`) |
| `custom.*` | | free-form keys for your own tools |

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | internal error (SQLite, JSON, I/O), a database written by a newer bd, or `doctor` found problems |
| 2 | invalid input, a cycle, or a refusal (such as `--force` on a command that has none) |
| 3 | not found, or no workspace |
| 4 | claim conflict: already claimed (a live claim, even your own actor's, without its `--token`), not claimable, not ready, another actor's live claim (`--take-over` takes it over), or lease lost |
| 5 | busy: the database write lock, a checkout's agent mutex or saved credentials stayed locked past `--busy-timeout-ms`; retry |
| 6 | event cursor older than what retention kept |
| 7 | access denied (remote): no token, an invalid or expired one, or one that does not allow this; a refused sign-in; a `max_claims` limit |
| 8 | bd server unreachable, its certificate not trusted, or a server failure: the command did not take effect |
| 9 | a write reached the bd server but its answer was lost: check before running it again |
| 13 | stale optimistic-concurrency guard (`--if-revision`, `--if-status`, `--if-assignee`) |
| 130 | `bd agents watch` interrupted twice |

With `--json`, errors are printed to stderr as `{"error": {"code",
"message", "exit_code"}}`. The codes:

| code | exit |
|---|---|
| `sqlite`, `json`, `io`, `schema_too_new` | 1 |
| `invalid`, `cycle`, `refused` | 2 |
| `not_found`, `no_workspace` | 3 |
| `already_claimed`, `not_claimable`, `not_ready`, `not_owner`, `lease_lost` | 4 |
| `busy` | 5 |
| `events_truncated` | 6 |
| `unauthorized` | 7 |
| `remote` | 8 |
| `answer_lost` | 9 |
| `conflict` | 13 |
