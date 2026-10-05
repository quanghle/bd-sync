# Contributing

bd is a Rust workspace: the engine library `crates/bd-core`, the commands
(`crates/bd-cli`, a library), `bd serve` (`crates/bd-server`, a library over
`bd-cli`) and the binary `bd` (`crates/bd`). [AGENTS.md](AGENTS.md) is the full guide for
agents and people alike: architecture, conventions and the task workflow.

## Tracking work

This repository tracks its own work with bd (`.bd/bd.db`, local and
gitignored). Use it instead of markdown TODO lists:

```bash
bd prime                                   # context: your actor, claims, ready work, playbooks, memories
bd ready                                   # unblocked work, in queue order
bd claim <id>                              # or: bd claim --next
bd create "Found while working" --dep discovered-from:<id>
bd close <id> --reason "what was done"
```

## Build and test

```bash
cargo build --release                      # target/release/bd
cargo test --workspace                     # engine + CLI tests
cargo clippy --workspace --all-targets && cargo fmt --all
target/release/bd bench --workers 8        # throughput + invariant check on a scratch database
```

CI (`.github/workflows/ci.yml`) runs `cargo fmt --all --check`, then clippy
with `-D warnings` and the tests on Linux, macOS and Windows, plus a check on
the minimum supported Rust version (`rust-version` in `Cargo.toml`), so keep
all three platforms and the MSRV building. Integration tests that spawn `bd`
clear the agent-session variables (`BD_SESSION`, `CLAUDE_CODE_SESSION_ID`,
`COPILOT_AGENT_SESSION_ID`, `CODEX_THREAD_ID`, ...) per command, so the tests
pass inside an agent session too.

## Dependencies

Add dependencies so that `Cargo.lock` stays compatible with the MSRV:

```bash
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo add <crate>
cargo +1.99 check --workspace --all-targets --locked
```

## Conventions

The rules that keep the engine's guarantees are in
[AGENTS.md](AGENTS.md#conventions--patterns). In short:

- Every mutation goes through `Store::write`, and appends its events with
  `WriteCtx::emit` in the same transaction.
- Changes that can affect readiness call `graph::recompute`; `bd doctor`
  checks the blocked flags against a full recompute.
- A lease exists if and only if the issue is `in_progress`, held by its
  assignee. Ending or taking over another actor's claim needs `take_over`,
  never `force`.
- Commands print and read only through `io.rs`, so `bd serve` can run them
  in-process; every new command needs a class in `cli::access`.

## Documentation

User documentation lives in [docs/](docs/); the [README](README.md) links each
page. Update the page a change affects in the same change.

## Releases

Releases are built by `.github/workflows/release.yml` when a `vX.Y.Z` tag is
pushed: see [RELEASING.md](RELEASING.md).

## Layout

```
crates/bd-core/src/   store (WAL, transactions, busy handling) · schema · issues · graph (deps + blocked state)
                      ready · claims (leases) · events · comments · memory · config · transfer (JSONL)
                      metrics · doctor · queries (read API) · gates (conditions, arming, evaluation)
                      policy (what a request's access token may override) · requests (idempotency records)
                      · playbook/ (model + strict parsing · template · loader · bundle (a remote client's
                      playbook files) · compile · run · extract) · agents/ (harness sets: strict loading,
                      manifests, MCP definitions, agents_changed events)
crates/bd-core/tests/ engine integration tests (graph semantics, leases with a manual clock, concurrency,
                      playbook runs and gates, write policies)
crates/bd-cli/src/    lib (run, execute, dispatch) · cli/ (clap; access: what bd serve runs for clients)
                      · commands/ · playbooks · gates (gh probes) · batch · fmt · logging
                      · backup (bd backup and bd serve's backups: snapshots, naming, retention)
                      · io (stdio and files, or a captured request) · mcp/ (MCP tools over stdio)
                      · remote/ (client) · credentials (bd remote login) · tokens (roles, token summaries)
                      · protocol (wire format) · stream (reading streamed answers) · agents (bd agents)
                      + agents/ (checkout, lock, mcp_file, sync, approve, show, hook, watch) · hook (session
                      hook output per harness)
crates/bd-server/src/ serve/ (bd serve: listen, routes, exec, sign-in endpoints, MCP endpoint, check)
                      · stream (streamed answers) · mcp_http (MCP over HTTP) · jobs (background jobs:
                      reclaim, gate checks, agent sets, backups) · follow (long polls) · server_db (server.db)
                      · auth/ (access tokens, accounts and their actors) · oauth/ (sign-in: one rule engine
                      for every provider, GitHub, admission, refresh) · oidc/ · authorizer · oauth_server/
                      (the authorization server for MCP clients: authorize/, token, clients, metadata
                      documents, pages)
crates/bd/src/        main (the binary; hands bd serve and bd bench to bd-cli) · bench
crates/bd/tests/      end-to-end CLI tests; remote.rs runs real bd serve and client processes
```

