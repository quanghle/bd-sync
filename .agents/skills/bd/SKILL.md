---
name: bd
description: Use when working in a repository that tracks tasks with bd (it has a .bd/ directory). Trigger when the user asks to find ready work, claim, renew, or close tasks, record dependencies, blockers, or discovered follow-up work, leave handoff comments, store durable project memories, or recover project context.
---

# bd

bd is this repository's shared task tracker: a dependency-aware work queue in `.bd/bd.db` (SQLite, WAL). Use it instead of markdown TODO files or local notes for any work another session or agent may need to see.

## First step

Run `bd prime`. It prints the workflow, your current claims, the top of the ready queue, and project memories. Outside a workspace it prints nothing; `bd info` shows which workspace is active.

## Workflow

1. Find work: `bd ready` (queue order), `bd list --status in_progress`, `bd blocked`.
2. Inspect before editing: `bd show <id>` (blockers, dependencies, comments, lease).
3. Claim atomically: `bd claim <id>`, or `bd claim --next` for the head of the queue. Note the lease token it prints.
4. During long work, renew the lease: `bd heartbeat <id> --token <t>`. If it fails, stop: the claim was lost.
5. Record follow-up work: `bd create "Title" -d "why and what" --dep discovered-from:<id>`; order work with `bd dep add <issue> <depends-on>`.
6. Finish: `bd close <id> --reason "..."` (add `--failed` if it failed), or give it back with `bd release <id>`.

## Playbooks and gates

- Repeatable multi-step work lives in `.bd/playbooks/*.toml`: `bd playbook list`, then `bd playbook run <name> --var key=value` (preview with `bd playbook plan`). Its steps are ordinary issues `<run>.<step>`: work them with `bd ready --run <run>`, claim, close.
- `bd playbook status <run>` shows every step and what it waits on. Runs close themselves when their last step closes.
- Gates (`<run>.gate-<step>`) hold a step until a person approves, a timer passes, an issue closes, or a GitHub PR/run finishes. Never claim them: `bd gate list`, `bd gate check`, and `bd gate resolve <id>` when a person has approved. `bd prime` lists gates waiting on a person.

## Rules

- Prefer `--json` when parsing output.
- Exit code 4 is a claim conflict (held by someone else, or not ready); 13 is a stale `--if-revision` guard. Re-read instead of retrying blindly.
- Do not close or mutate tasks unless the work is actually done.
- Store durable insights with `bd remember "..."`; search them with `bd memories <query>`.
