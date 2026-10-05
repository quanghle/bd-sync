# Features

bd is a dependency-aware work queue for agents and humans: issues, typed
dependencies, deterministic ready work, leased claims and an event log, on one
SQLite database in WAL mode.

- **Task lifecycle**: `open → in_progress → closed`, plus `blocked`, `deferred`, `pinned` ([Statuses](concepts.md#statuses))
- **Typed dependency graph**: `blocks`, `conditional-blocks`, `parent-child`, `waits-for` gate readiness; informational edges (`related`, `discovered-from`, …) never do. Cycles and hierarchy deadlocks are rejected at write time. ([Dependency types](concepts.md#dependency-types-bd-dep-add-issue-depends_on--t-type))
- **Deterministic ready work**: a materialized blocked flag maintained in the same transaction as every change, and a total queue order (policy, then id) ([Ready-work order](concepts.md#ready-work-order))
- **Leased atomic claiming**: claims run under SQLite's write lock and return a lease with a fencing token; a live claim is its holder's alone, and taking one over takes `--take-over` ([Claims](concepts.md#claims-leases-and-recovery))
- **Crash recovery**: expired leases are reclaimed after a grace window (automatically by `claim --next`, and every minute by `bd serve`); WAL makes every transaction atomic ([Claims](concepts.md#claims-leases-and-recovery))
- **Optimistic concurrency**: per-issue revisions and `--if-revision/--if-status/--if-assignee` guards (exit code 13 on conflict) ([Optimistic concurrency](concepts.md#optimistic-concurrency))
- **Comments, durable memory, and transactional event history** with gapless, commit-ordered sequence numbers ([Event history](concepts.md#event-history), [Comments and memory](concepts.md#comments-and-memory))
- **Playbooks and gates**: repeatable multi-step work declared once in TOML and run atomically as `<run>.<step>` issues; human, timer, issue, and GitHub gates that arm when their step could start ([Playbooks](playbooks.md))
- **Remote server**: `bd serve` shares workspaces over HTTPS with laptops, CI runners and cloud agents; the same `bd` binary is the client, with access tokens (roles, and human or agent kinds) that an admin creates or people get by signing in with GitHub, and retries that apply a write once. The server also reclaims dead workers' leases, checks gates and takes backups on its own ([Remote server](remote.md))
- **Agent assets**: a workspace serves skills and MCP server definitions per harness (Claude Code, Codex, Copilot CLI); checkouts pull them into each harness's own places, new or changed skills and MCP definitions only once a person approves them (`bd agents approve`) ([Agent skills and MCP definitions](agents.md))
- **Per-session actors**: each agent session (Claude Code, Copilot CLI, Codex) acts as its own actor `<user>/<session>` with no setup, so concurrent sessions never share claims ([Actors](concepts.md#actors))
- **Extras**: JSONL export/import that reads beads exports ([Migrating from Go beads](beads.md#migrating-from-go-beads)), `bd batch` (many writes, one transaction; [Commands](commands.md)), `bd bench` ([Benchmarks](benchmarks.md)), and local observability: structured logs, timing, Prometheus metrics, `bd doctor` ([Observability](observability.md))
- **Embeddable**: the engine is a Rust library, `crates/bd-core`; the commands (`crates/bd-cli`) and `bd serve` (`crates/bd-server`) are libraries built on it, and the binary `bd` (`crates/bd`) links both ([Modes of operation](modes.md#embedded-library))
