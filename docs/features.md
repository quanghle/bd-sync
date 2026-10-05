# Features

bd is a dependency-aware work queue for agents and people: issues, typed
dependencies, deterministic ready work, leased claims and an event log, on
one SQLite database in WAL mode.

**Coordination**

- **Task lifecycle**: `open → in_progress → closed` (done or failed), plus
  `blocked`, `deferred` and `pinned` ([Statuses](concepts.md#statuses)).
- **Typed dependency graph**: `blocks`, `conditional-blocks`,
  `parent-child` and `waits-for` gate readiness; informational edges never
  do. Cycles are refused when written
  ([Dependency types](concepts.md#dependency-types)).
- **Deterministic ready work**: a blocked flag maintained in the same
  transaction as every change, and a total queue order
  ([Ready work](concepts.md#ready-work)).
- **Leased atomic claims**: claims run under SQLite's write lock and return
  a lease with a fencing token. A live claim is its holder's alone; taking
  one over takes `--take-over` and is recorded
  ([Claims](concepts.md#claims-leases-and-recovery)).
- **Crash recovery**: dead claims are reclaimed after a grace window, by
  `claim --next` and every minute by `bd serve`.
- **Optimistic concurrency**: per-issue revisions and
  `--if-revision`/`--if-status`/`--if-assignee` guards
  ([Optimistic concurrency](concepts.md#optimistic-concurrency)).
- **History and memory**: a transactional event log with gapless,
  commit-ordered sequence numbers; comments; durable project memories
  ([Event history](concepts.md#event-history)).
- **Per-session actors**: each agent session acts as its own actor
  `<user>/<session>` with no setup, so concurrent sessions never share
  claims ([Actors](concepts.md#actors)).

**Workflows**

- **Playbooks**: repeatable multi-step work declared once in TOML or JSON
  and run atomically as `<run>.<step>` issues, with loops, conditions,
  groups, inheritance and fan-in ([Playbooks](playbooks.md)).
- **Gates**: human, timer, issue, GitHub pull request and GitHub Actions
  run gates that arm when their step could start, with timeouts and
  escalation ([Gates](playbooks.md#gates)).

**Sharing**

- **Remote server**: `bd serve` shares workspaces over HTTPS; the same `bd`
  binary is the client. Access tokens have roles, kinds (human or agent),
  workspace scopes and claim limits, and retries apply a write exactly
  once. The server also reclaims dead claims, checks gates and takes
  backups on its own ([Remote server](remote.md)).
- **Sign-in**: people get their own tokens by signing in with any OpenID
  Connect provider, from the command line (device flow) or a browser,
  under rules or the admin's own authorizer ([Signing in](sign-in.md)).
- **MCP server**: bd's coordination tools over MCP, on stdio (`bd mcp`)
  and over Streamable HTTP per workspace, with an OAuth 2.1 authorization
  server for clients that sign people in ([MCP server](mcp.md)).
- **Agent assets**: a workspace serves skills and MCP server definitions
  per harness (Claude Code, Codex, Copilot CLI); checkouts pull them, with
  new or changed ones written only once a person approves them, and
  session-start hooks keep them current ([Agent assets](agents.md)).

**Operations**

- **Data**: JSONL export and import (which also reads beads exports),
  `bd batch` for many writes in one transaction, and verified backups
  ([Commands](commands.md#data)).
- **Observability**: structured logs, timing, Prometheus metrics for
  workspaces and the server, and `bd doctor`
  ([Observability](observability.md)).
- **Benchmarks**: `bd bench` measures throughput and verifies the
  invariants end to end ([Benchmarks](benchmarks.md)).
- **Embeddable**: the engine is a Rust library, `bd-core`; the commands
  (`bd-cli`) and the server (`bd-server`) are libraries built on it
  ([Embedded library](modes.md#embedded-library)).
