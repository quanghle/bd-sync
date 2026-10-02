# Agent Instructions

This repository tracks its work with **bd**, the Rust coordination engine built here. Issues live in `.bd/bd.db` (local SQLite in WAL mode, gitignored). Use bd for all task tracking: no markdown TODO lists, no ad hoc memory files.

Run `bd prime` for current context: your claims, ready work, and project memories. Session-start hooks run it automatically in Claude Code and Copilot CLI.

## Task tracking with bd

### Core loop

```bash
bd ready                                # unblocked work, in queue order
bd show <id>                            # details, blockers, comments, lease
bd claim <id>                           # or `bd claim --next`; atomic, returns a lease token (`--token <t>` renews your own)
bd heartbeat <id> --token <t>           # renew the lease during long work (default TTL 5m)
bd close <id> --reason "what was done"  # add --failed if it failed; `bd release <id>` gives it back
```

### Recording work

```bash
bd create "Title" -d "why and what" -t task -p 2    # types: task bug feature epic chore; priority 0-4 (0 = critical)
bd create "Found while working" --dep discovered-from:<id>
bd create "Subtask" --parent <epic-id>
bd dep add <issue> <depends-on>                     # issue waits until depends-on closes
bd comment add <id> "context for whoever picks this up"
bd remember "durable project insight"               # shown by bd prime; search with bd memories <query>
```

### Rules

- Create or claim an issue before starting work, and close it when the work is done.
- Use `--json` when parsing output.
- Exit code 4 means a claim conflict: someone else holds it (another actor, or another session under your own actor name: a second `bd claim` of a live claim needs its `--token`), or it is not ready. Closing, releasing, reassigning, moving out of `in_progress` or deleting another actor's live claim fails with exit 4 naming its holder, `--force` or not (`--force` only gets past open children, blockers, dependents and unfinished runs); `--take-over` takes it over (recorded in the event history), so pass it only when you mean to. Exit code 13 means a stale `--if-revision`/`--if-status`/`--if-assignee` guard: re-read before retrying. In a remote workspace (`.bd/remote.toml`), exit code 7 means the access token (`BD_TOKEN`, or one saved by `bd remote login`) is missing or not allowed, 8 means the bd server is unreachable (the command did not take effect), and 9 means a write's answer was lost: it may have taken effect, so check (`bd show`) before running it again; `bd remote show` checks the connection and the token.
- If `bd heartbeat` fails, stop working on that issue: the claim was released, reclaimed, or taken over.
- Each agent session acts as its own actor, `<user>/<session>`, derived from the session id its harness sets (`$CLAUDE_CODE_SESSION_ID`, `$COPILOT_AGENT_SESSION_ID`, `$CODEX_THREAD_ID`) and `$BD_SESSION`; `bd prime` and `bd claim` show it. Do not set `BD_ACTOR` to a name other sessions use. If `bd prime` warns that you are the plain default actor and it holds claims, run each of your bd commands with `BD_SESSION=<name>`, and leave claims you did not take to their holder.
- After `/clear`, a resume, or in a subagent with its own session id, your earlier claims belong to another actor of your user: `bd prime` lists them under "Held by other sessions of yours" with the takeover command (`bd update <id> --assignee <you> --take-over`, which prints the new lease token to use from then on). Take one over only if this session is continuing that work. An actor named outright (`--actor`, `BD_ACTOR`) has no other sessions: other names are other actors, even under the same first segment. To hand a claimed issue to a subagent, have it take the claim over, or run its bd commands with `BD_ACTOR=<your actor>`.

### Session completion

1. Close finished issues; create issues for remaining work.
2. When code changed, run the quality gates under Build & Test.
3. Report `git status`. Do not commit or push unless explicitly asked.

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

## Project: Rust `bd` coordination engine

### Build & Test

```bash
cargo build --release                 # target/release/bd
cargo test --workspace                # engine + CLI tests
cargo clippy --workspace --all-targets && cargo fmt --all
target/release/bd bench --workers 8   # throughput + invariant verification on a scratch DB
```

CI (`.github/workflows/ci.yml`) runs fmt, then clippy `-D warnings` and the tests on Linux, macOS, and Windows, plus an MSRV check, so keep all three platforms building. Releases are built by `.github/workflows/release.yml` when a `vX.Y.Z` tag is pushed; see RELEASING.md (and the `release` playbook in `.bd/playbooks/`).

### Architecture Overview

Rust re-implementation of beads as a coordination engine on SQLite WAL (see README.md).

- `crates/bd-core` (library): `store.rs` (WAL pragmas, busy handler, `Store::write` = one `BEGIN IMMEDIATE` transaction with a `WriteCtx`), `schema.rs` (migrations via `PRAGMA user_version`), `issues.rs` (lifecycle), `graph.rs` (typed edges, cycle/hierarchy checks, materialized `is_blocked`), `ready.rs`, `claims.rs` (leases, fencing tokens, reclaim), `events.rs`, `comments.rs`, `memory.rs`, `transfer.rs` (JSONL, beads-compatible import), `metrics.rs`, `doctor.rs`, `queries.rs` (read API trait), `gates.rs` (gate conditions in `metadata.gate`, arming via `graph::recompute`, local evaluation, escalation), `requests.rs` (idempotency records: a request id stored in the same transaction as its write), `policy.rs` (claim ownership for every caller: ending or taking over another actor's live claim needs the operation's `take_over`, never its `force`, and is recorded as `claim_override` in its event; and what a `bd serve` request may override, set per transaction with `WriteCtx::set_policy`: other actors' claims need an admin token, human gates a human one), `playbook/` (playbook files: strict parsing, `{{var}}` templates and conditions, `extends`/`expand` loading, bundles of a remote client's playbook files that the server loads without touching its disk, compile to a size-limited `Plan`, runs, extract).
- `crates/bd-cli` (binary `bd`): clap grammar in `cli.rs`; mutations are `exec_*` functions over `WriteCtx` in `commands.rs` so `batch.rs` can run them in one transaction; `bench.rs` is the throughput and invariant harness; `actor.rs` resolves who a command acts as (`--actor`, `$BD_ACTOR`, else the user, as `<user>/<session>` in an agent session) and implements `bd hook session-start`; `playbooks.rs` and `gates.rs` implement `bd playbook` and `bd gate` (GitHub gates shell out to `gh`, outside any write transaction; in a remote workspace `playbooks.rs` sends the checkout's playbooks with the command as a bundle, behind the hidden `--playbook-bundle` flag). Remote workspaces: `serve.rs` (`bd serve`: tokio/hyper with rustls on `ring`; runs each request's command line in-process via `execute` with captured I/O), `jobs.rs` (`bd serve`'s background jobs in every workspace under the root: lease reclaim, gate checks, `VACUUM INTO` backups with retention, pruning of request records; jittered per-workspace timers, small lanes of blocking threads, runs `bd reclaim`/`bd gate check` as actor `bd-serve` with captured I/O), `follow.rs` (long polls: `events --since N --wait D` waits for a matching event without a command slot or connection, woken by a per-workspace watcher of the events head that commands, background jobs and a timer kick; `--max-followers`, `--max-wait`), `auth.rs` (access tokens in `<root>/tokens.json`, roles, human/agent kinds, actor binding), `remote.rs` (client: `--remote`/`BD_REMOTE`/`.bd/remote.toml`, retries with request ids), `credentials.rs` (tokens saved per server by `bd remote login`, mode 0600), `protocol.rs` (wire format), `stream.rs` (streamed answers: frames, a bounded pipe, the client's reader), `io.rs` (stdio and files, or a request's capture).

### Conventions & Patterns

- Every mutation goes through `Store::write` and appends its events with `WriteCtx::emit` in the same transaction; never write SQL outside a write transaction.
- Any change that can affect readiness must call `graph::recompute` with the right seeds; `bd doctor` (`blocked_drift`) verifies against a full recompute.
- Keep the lease invariant: a lease exists iff the issue is `in_progress` and the holder equals the assignee.
- A path that ends or takes over a claim (closing, releasing, reassigning, leaving `in_progress`, deleting, importing, reclaiming inside `lease.grace`) calls `WriteCtx::check_claim_override` (or `check_claim_overrides` for several) with the operation's `take_over`, before any refusal its `force` gets past, so batches, playbooks and imports get the same answer and the first refusal names the holder. Never let a structural flag (`force`, `cascade`) or a guard (`--if-assignee`) imply a takeover. A live claim is never claimed twice without its lease token.
- Keep indexes minimal: each index is extra pages written per claim/close (see `bd bench`).
- Playbook runs and groups are identified by `metadata.playbook.role` (`run`/`group`): they close themselves when their subtree closes; keep that metadata when touching run issues.
- Commands print and read only through `io.rs` (`outln`, `errln`, `with_stdout`, `read_input`, `send_file`), never `println!`, stdin or client-named files directly, so `bd serve` can run them in-process and capture their I/O. Admin-only operations call `io::require_admin`, machine-local ones `io::require_local`; new commands also need a class in `serve::access`.
- Overrides that depend on the caller's token (ending other actors' claims, getting past human gates) are checked in bd-core against the transaction's `Policy` (`App::write` sets it from `io::policy()`), at the point of the override, so they hold in batches and playbooks; a new override path must check it too. GitHub probes go through `gates::probe_github`, which enforces `gate.repos`.
- AGENTS.md and CLAUDE.md are identical; edit both.
