# Contributing

bd is a Rust workspace: the engine library `crates/bd-core` and the CLI
`crates/bd-cli` (binary `bd`). [AGENTS.md](AGENTS.md) is the full guide for
agents and people alike: architecture, conventions and the task workflow.

## Tracking work

This repository tracks its own work with bd (`.bd/bd.db`, local and
gitignored). Use it instead of markdown TODO lists:

```bash
bd prime                                   # context: your actor, claims, ready work, memories
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
cargo +1.85 check --workspace --all-targets --locked
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
  in-process; every new command needs a class in `serve::access`.

## Documentation

User documentation lives in [docs/](docs/); the [README](README.md) links each
page. Update the page a change affects in the same change. `AGENTS.md` and
`CLAUDE.md` are identical: edit both.

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
crates/bd-cli/src/    cli (clap) · commands · playbooks · gates (gh probes) · batch · bench · fmt · logging
                      io (stdio and files, or a captured request) · serve (bd serve) · jobs (its background
                      jobs: reclaim, gate checks, agent sets, backups) · auth (access tokens)
                      · oauth (sign-in: GitHub, providers, refresh) · oidc · authorizer · remote (client) · credentials (bd remote login)
                      · protocol (wire format) · stream (streamed answers) · agents (bd agents) + agents/
                      (checkout, lock, mcp_file, sync, approve, show, hook, watch) · hook (session hook
                      output per harness)
crates/bd-cli/tests/  end-to-end CLI tests; remote.rs runs real bd serve and client processes
```

