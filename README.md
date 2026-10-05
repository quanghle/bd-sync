# bd — a coordination engine for agents, on SQLite WAL

`bd` is a Rust re-implementation of [beads](https://github.com/gastownhall/beads)
(the `bd` issue tracker for AI coding agents) as a fast, embeddable
coordination engine:

- **Dependency-aware work queue**: typed dependencies gate readiness, and
  `bd ready` gives one deterministic queue order
- **Leased atomic claims**: two agents never take the same issue; dead
  workers' claims come back after a grace window
- **Transactional event log**, comments and durable memory, with optimistic
  concurrency guards
- **Playbooks and gates** for repeatable multi-step work
- **Remote server**: `bd serve` shares workspaces over HTTPS with access
  tokens and sign-in with GitHub or any OpenID Connect provider
- **Agent assets**: skills and MCP definitions served per harness (Claude
  Code, Codex, Copilot CLI)

It ships as an engine library (`crates/bd-core`), the commands (`crates/bd-cli`)
and the server (`crates/bd-server`) as libraries, and the binary `bd` (`crates/bd`). See [Features](docs/features.md) for the full list.

## Install

Download a prebuilt binary from the
[releases](https://github.com/quanghle/bd-sync/releases) (checksums and
attestations: [Install](docs/install.md)), or build from source:

```bash
cargo install --path crates/bd          # installs ~/.cargo/bin/bd
```

Coming from Go beads? [Migrate](docs/beads.md#migrating-from-go-beads) first.

## Quick start

```bash
bd init --prefix demo                       # creates .bd/bd.db (WAL)
bd create "Design schema" -p 1
bd create "Implement API" -p 2 --dep demo-xyz   # blocked until demo-xyz closes
bd ready                                    # unblocked work, queue order
bd claim --next                             # atomic claim + 5m lease (prints token)
bd heartbeat demo-xyz --token 42            # renew while working
bd close demo-xyz --reason "merged" --token 42
bd prime                                    # agent context: claims, ready work, playbooks, memories
```

Agent loop: `bd claim --next --json` → work, heartbeating every few minutes
→ `bd close <id> --token <t>` (or `--failed`). If `heartbeat` exits 4, the
lease was lost (reclaimed or taken over): stop working on that issue. A
claim is protected from every other actor name, not from other sessions
sharing its own, so each agent session acts as its own actor
`<you>/<session>`, derived from the session id its agent harness sets
(Claude Code, Copilot CLI, Codex) or `BD_SESSION`; see
[Actors](docs/concepts.md#actors).

## Documentation

| page | covers |
|---|---|
| [Features](docs/features.md) | everything bd does, with links |
| [Install](docs/install.md) | prebuilt binaries, checking them, building from source |
| [Differences from beads](docs/beads.md) | what bd keeps and changes from beads, and migrating from Go beads |
| [Concepts](docs/concepts.md) | statuses, dependency types, ready-work order, claims and leases, optimistic concurrency, events, memory, actors |
| [Modes of operation](docs/modes.md) | local workspaces and their backups, remote workspaces, the embedded library |
| [Playbooks and gates](docs/playbooks.md) | repeatable multi-step work, runs, human/timer/issue/GitHub gates |
| [Remote server](docs/remote.md) | `bd serve`, access tokens, sign-in with GitHub or OIDC, background jobs and backups, clients, followers |
| [Agent skills and MCP definitions](docs/agents.md) | serving, pulling and approving agent assets; session-start hooks |
| [MCP server](docs/mcp.md) | bd's tools over MCP: `bd mcp` (stdio) and `bd serve`'s `/w/<name>/mcp` (Streamable HTTP) setup, actors, tool catalog, results and errors (MCP `2026-07-28` and `2025-11-25`) |
| [Command reference](docs/commands.md) | commands, global options, environment variables, configuration, exit codes |
| [Observability](docs/observability.md) | logs, timing, metrics, `bd doctor` |
| [Benchmarks](docs/benchmarks.md) | `bd bench` modes and results |
| [Security](docs/security.md) | trust boundaries, tokens, credentials, agent assets, reporting vulnerabilities |
| [Contributing](CONTRIBUTING.md) | building, testing, conventions, layout |
| [Releasing](RELEASING.md) | how releases are built, checked and published |

## License

MIT: see [LICENSE](LICENSE).
