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

## Playbooks and agent skills

This repository's playbooks and agent skills are published to its bd
workspace. Their source is `.bd/source/`: `playbooks/*.toml` and
`agents/<harness>/skills/` (`claude` and `codex`). To change one:

1. Edit it under `.bd/source/` and have it reviewed and merged like code.
2. An admin runs `bd publish --dry-run`, then `bd publish` (it needs a
   person's admin token).
3. Each client runs `bd agents approve` in a terminal (agent sessions
   cannot), which places the files in `.bd/approved/playbooks/`,
   `.claude/skills/` and `.agents/skills/`.

Those pulled copies are gitignored; never edit them in place. Claude Code's
bd skill comes from `plugins/bd`. [docs/agents.md](docs/agents.md) and
[docs/playbooks.md](docs/playbooks.md) hold the details.

## Build and test

```bash
cargo build --release                      # target/release/bd
cargo test --workspace                     # engine + CLI tests
cargo clippy --workspace --all-targets && cargo fmt --all
target/release/bd bench --workers 8        # throughput + invariant check on a scratch database
bash scripts/test-packaging.sh             # install script, packaging templates and their rendering
```

`scripts/test-packaging.sh` needs bash, curl, tar and python3 (or zip); node,
ruby and shellcheck are used when present. It checks that the install scripts
and templates name the same targets and files as the release workflow, runs
`install.sh` against a `file://` fixture and renders the packaging. On Windows
`scripts/test-install.ps1 -Binary target/release/bd.exe` runs `install.ps1`
with the real binary.

CI (`.github/workflows/ci.yml`) runs `cargo fmt --all --check`, then clippy
with `-D warnings` and the tests on Linux, macOS and Windows, plus a check on
the minimum supported Rust version (`rust-version` in `Cargo.toml`), so keep
all three platforms and the MSRV building. A `packaging` job runs shellcheck on
the scripts and `scripts/test-packaging.sh` on Linux and macOS, and the Windows
test job runs `scripts/test-install.ps1`. Integration tests that spawn `bd`
clear the agent-session variables (`BD_SESSION`, `CLAUDE_CODE_SESSION_ID`,
`COPILOT_AGENT_SESSION_ID`, `CODEX_THREAD_ID`, ...) per command, so the tests
pass inside an agent session too.

`.github/workflows/deny.yml` runs cargo-deny (advisories, bans, licenses and
sources, with the policy in `deny.toml`) on pull requests and pushes to main
that touch a `Cargo.toml`, `Cargo.lock`, `deny.toml` or the workflow itself,
daily at 06:17 UTC so an advisory published after a merge is seen, and by hand
from the Actions tab. See [Dependencies](#dependencies).

## Dependencies

Add dependencies so that `Cargo.lock` stays compatible with the MSRV:

```bash
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo add <crate>
cargo +1.99 check --workspace --all-targets --locked
```

The cargo-deny job runs the version and SHA-256 pinned in
`.github/workflows/deny.yml`. The same check locally, with that version:

```bash
cargo deny --all-features --locked check
```

It covers the crate graph cargo-deny builds: every workspace member, target and
feature, with dev-dependencies. That is 236 of the 253 packages in `Cargo.lock`
at the time of writing; to recount,
`cargo deny --all-features --locked list -f tsv` prints a header, then one row
per crate. The others are optional dependencies of dependencies that no enabled
feature turns on, so they are never compiled. An advisory on one does not fail
the job, and a change that enables one brings it into the graph, and the
manifest change starts the job.

Advisories come from RustSec and match by crate name and version, not by
whether bd reaches the code, and a crate with no advisory passes. Dependabot
alerts read all of `Cargo.lock` from a different database, so they are a
separate channel.

A failed run goes red on main and repeats daily until fixed. It blocks nothing:
main has no branch protection and `release.yml` does not depend on it. GitHub
notifies the account that last changed the cron line, according to that
account's notification settings, and nothing else happens by itself. The run
and its log are public.

Whoever sees a failure files a bd issue, then does one of two things:

- Update the crate, keeping the lock MSRV-compatible as above, and remove any
  `ignore` entry it had, because a stale entry fails.
- Accept the finding: an `ignore` entry in `deny.toml` with its `id` and a
  `reason` that says why it is acceptable and carries `review by YYYY-MM-DD`,
  at most 90 days out, and a bd issue id, with that issue created with
  `--defer <that date>` so it reaches `bd ready` on the date.

`deny.toml` is public, so a reason holds no exploit detail beyond the advisory
and no id of a private security finding. A vulnerability that may be reachable,
or a finding that needs a code change, gets a bug issue and goes to the
maintainer before it is accepted.

An outage of GitHub, crates.io or the advisory database also fails the job;
rerun it. A tool too old to read the database fails it too: change the version
and hash together in one reviewed change, with the hash computed from the
download and matched against the release's `.sha256` file. Dependabot does not
bump them.

GitHub disables schedules on public repositories after 60 days without
activity, and that raises no failure. `gh workflow enable deny.yml` restores
it.

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

Help text: command summaries are imperative phrases ("List ready work"), at
most 80 characters, capitalized, with no trailing period; every visible flag,
argument and possible value has help in the same style, and global flags fit
on one line of 80 characters. Detail goes in a long help (`long_about`), and
examples in an `Examples:` block of `after_long_help`, each of which must
parse. Help states the runtime defaults and validator bounds that clap cannot
show, and authorization notes name the exact case they apply to (live-claim
overrides, admin-only commands). Flags that mean the same thing share their
wording (the constants and suffix macros in `cli/mod.rs`); durations are
`DURATION`, times `TIME`. Help uses no first- or second-person pronouns and
names no products in sign-in examples. The tests in `cli/tests.rs` check
these rules on the help as written.

## Documentation

User documentation lives in [docs/](docs/); the [README](README.md) links each
page. Update the page a change affects in the same change.

## Releases

Releases are built by `.github/workflows/release.yml` when a `vX.Y.Z` tag is
pushed: see [RELEASING.md](RELEASING.md).

## Layout

```
scripts/              install.sh, install.ps1 (installers), render-packaging.sh (release packaging),
                      test-packaging.sh, test-install.ps1 (their tests)
packaging/            templates rendered per release: homebrew/, winget/, npm/ (see RELEASING.md)
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
                      · remote/ (client) · credentials (bd remote login) · keychain (login --human)
                      · tokens (roles, token summaries)
                      · protocol (wire format) · stream (reading streamed answers) · agents (bd agents)
                      + agents/ (checkout, lock, mcp_file, sync, approve, show, hook, watch) · hook (session
                      hook output per harness)
crates/bd-server/src/ serve/ (bd serve: listen, routes, exec, sign-in endpoints, MCP endpoint, check)
                      · stream (streamed answers) · mcp_http (MCP over HTTP) · jobs (background jobs:
                      reclaim, gate checks, agent sets, backups) · follow (long polls) · server_db (server.db)
                      · webauthn (passkey registrations and assertions verified on ring) · passkeys
                      (passkeys and add allowances in server.db, bd serve passkey)
                      · auth/ (access tokens, accounts and their actors) · oauth/ (sign-in: one rule engine
                      for every provider, GitHub, admission, refresh) · oidc/ · authorizer · secrets
                      (secrets fetched by the admin's command) · helper (running such commands) · oauth_server/
                      (the authorization server for MCP clients: authorize/, token, clients, metadata
                      documents, pages)
crates/bd/src/        main (the binary; hands bd serve and bd bench to bd-cli) · bench
crates/bd/tests/      end-to-end CLI tests; remote.rs runs real bd serve and client processes
                      · bin/ (a private copy of the bd binary per build, so a rebuild during a run does
                      not swap it)
                      · piped/ (input written while output drains)
                      · pty/ (a pseudo-terminal, Linux and macOS)
```

