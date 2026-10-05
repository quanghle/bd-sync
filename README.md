# bd — a coordination engine for agents, on SQLite WAL

`bd` is a fast, embeddable work queue for AI agents and the people working
with them:

- **Dependency-aware work queue**: typed dependencies gate readiness, and
  `bd ready` gives one deterministic queue order
- **Leased atomic claims**: two agents never take the same issue; dead
  workers' claims come back after a grace window
- **Transactional event log**, comments and durable memory, with optimistic
  concurrency guards
- **Playbooks and gates** for repeatable multi-step work
- **Remote server**: `bd serve` shares workspaces over HTTPS, with access
  tokens and sign-in through any OpenID Connect provider
- **MCP server**: the coordination loop as MCP tools, over stdio or HTTP
- **Agent assets**: skills and MCP definitions served per agent harness,
  written only once a person approves them

It ships as an engine library (`crates/bd-core`), the commands
(`crates/bd-cli`) and the server (`crates/bd-server`) as libraries, and the
binary `bd` (`crates/bd`). See [Features](docs/features.md) for the full
list.

## Install

Download a prebuilt binary from the
[releases](https://github.com/quanghle/bd-sync/releases) (checksums and
attestations: [Install](docs/install.md)), or build from source:

```bash
cargo install --path crates/bd          # installs ~/.cargo/bin/bd
```

Coming from beads? See [Differences from beads](docs/beads.md), which also
covers migrating.

## Quick start

```bash
bd init --prefix demo                       # creates .bd/bd.db (WAL)
bd create "Design schema" -p 1
bd create "Implement API" -p 2 --dep demo-xyz   # blocked until demo-xyz closes
bd ready                                    # unblocked work, queue order
bd claim --next                             # atomic claim + 5m lease (prints its token)
bd heartbeat demo-xyz --token 42            # renew while working
bd close demo-xyz --reason "merged" --token 42
bd prime                                    # agent context: claims, ready work, playbooks, memories
```

The agent loop: `bd claim --next --json`, then work, heartbeating every few
minutes, then `bd close <id> --token <t>` (or `--failed`). If `heartbeat`
exits 4, the lease was lost (reclaimed or taken over): stop working on that
issue. Each agent session acts as its own actor, `<you>/<session>`, derived
from the session id its harness sets or from `BD_SESSION`, so concurrent
sessions never share claims ([Actors](docs/concepts.md#actors)).

## Documentation

| page | covers |
|---|---|
| [Features](docs/features.md) | everything bd does, with links |
| [Install](docs/install.md) | prebuilt binaries, checking them, building from source |
| [Concepts](docs/concepts.md) | issues, statuses, dependencies, ready work, claims and leases, optimistic concurrency, events, memory, actors |
| [Modes of operation](docs/modes.md) | local workspaces and their backups, remote workspaces, the embedded library |
| [Playbooks and gates](docs/playbooks.md) | repeatable multi-step work, runs, gates |
| [Remote server](docs/remote.md) | `bd serve`, access tokens and roles, clients, background jobs, backups, followers, the protocol |
| [Signing in](docs/sign-in.md) | OpenID Connect providers, rules, accounts and actors, refreshing, authorizers, the device flow |
| [MCP server](docs/mcp.md) | `bd mcp` and `/w/<name>/mcp`, discovery, OAuth for MCP clients, the tool catalog |
| [Agent assets, sessions and hooks](docs/agents.md) | serving, pulling and approving skills and MCP definitions; session-start hooks; subagents |
| [Command reference](docs/commands.md) | commands, global options, environment variables, configuration, exit and error codes |
| [Observability](docs/observability.md) | logs, timing, metrics, `bd doctor` |
| [Benchmarks](docs/benchmarks.md) | `bd bench` modes, flags and results |
| [Security](docs/security.md) | trust boundaries, tokens, sign-in, OAuth, personal data, agent assets, reporting vulnerabilities |
| [Differences from beads](docs/beads.md) | how bd compares with beads, and migrating |
| [Contributing](CONTRIBUTING.md) | building, testing, conventions, layout |
| [Releasing](RELEASING.md) | how releases are built, checked and published |

## License

MIT: see [LICENSE](LICENSE).
