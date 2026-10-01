# Agent Instructions

This repository tracks its work with **bd**, the Rust coordination engine built here. Issues live in `.bd/bd.db` (local SQLite in WAL mode, gitignored). Use bd for all task tracking: no markdown TODO lists, no ad hoc memory files.

Run `bd prime` for current context: your claims, ready work, and project memories. Session-start hooks run it automatically in Claude Code and Copilot CLI.

## Task tracking with bd

### Core loop

```bash
bd ready                                # unblocked work, in queue order
bd show <id>                            # details, blockers, comments, lease
bd claim <id>                           # or `bd claim --next`; atomic, returns a lease token
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
- Exit code 4 means a claim conflict (someone else holds it, or it is not ready). Exit code 13 means a stale `--if-revision`/`--if-status`/`--if-assignee` guard: re-read before retrying.
- If `bd heartbeat` fails, stop working on that issue: the claim was released, reclaimed, or taken over.

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

### Architecture Overview

Rust re-implementation of beads as a coordination engine on SQLite WAL (see README.md).

- `crates/bd-core` (library): `store.rs` (WAL pragmas, busy handler, `Store::write` = one `BEGIN IMMEDIATE` transaction with a `WriteCtx`), `schema.rs` (migrations via `PRAGMA user_version`), `issues.rs` (lifecycle), `graph.rs` (typed edges, cycle/hierarchy checks, materialized `is_blocked`), `ready.rs`, `claims.rs` (leases, fencing tokens, reclaim), `events.rs`, `comments.rs`, `memory.rs`, `transfer.rs` (JSONL, beads-compatible import), `metrics.rs`, `doctor.rs`, `queries.rs` (read API trait), `gates.rs` (gate conditions in `metadata.gate`, arming via `graph::recompute`, local evaluation, escalation), `playbook/` (playbook files: strict parsing, `{{var}}` templates and conditions, `extends`/`expand` loading, compile to a `Plan`, runs, extract).
- `crates/bd-cli` (binary `bd`): clap grammar in `cli.rs`; mutations are `exec_*` functions over `WriteCtx` in `commands.rs` so `batch.rs` can run them in one transaction; `bench.rs` is the throughput and invariant harness; `playbooks.rs` and `gates.rs` implement `bd playbook` and `bd gate` (GitHub gates shell out to `gh`, outside any write transaction).

### Conventions & Patterns

- Every mutation goes through `Store::write` and appends its events with `WriteCtx::emit` in the same transaction; never write SQL outside a write transaction.
- Any change that can affect readiness must call `graph::recompute` with the right seeds; `bd doctor` (`blocked_drift`) verifies against a full recompute.
- Keep the lease invariant: a lease exists iff the issue is `in_progress` and the holder equals the assignee.
- Keep indexes minimal: each index is extra pages written per claim/close (see `bd bench`).
- Playbook runs and groups are identified by `metadata.playbook.role` (`run`/`group`): they close themselves when their subtree closes; keep that metadata when touching run issues.
- AGENTS.md and CLAUDE.md are identical; edit both.
