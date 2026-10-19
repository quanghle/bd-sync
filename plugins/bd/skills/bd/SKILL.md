---
name: bd
description: Use when working in a repository that tracks tasks with bd (it has a .bd/ directory). Trigger when the user asks to find ready work, claim, renew, or close tasks, record dependencies or discovered follow-up work, leave handoff comments, store project memories, or recover bd context after compaction.
---

# bd

bd is the repository's shared task tracker: a dependency-aware work queue with leased claims. Use it instead of markdown TODO files for any work another session or agent may need to see.

## Context

- Run `bd prime` first. It prints the workflow, your actor, your claims with their lease tokens, the top of the ready queue, and project memories. This plugin's SessionStart hook runs it for you.
- Run `bd prime` again after the conversation is compacted or summarized, after `/clear`, or on resume, unless the context already shows a fresh `# bd workflow context` (the plugin's hook prints one after compaction too): it lists your claims with their current lease tokens.
- If your context says to pass `--session agent-<id>` to bd (the subagent hook), pass it on every bd command; a command refused for lacking it names the corrected command to run.

## Core loop

1. `bd ready` lists unblocked work in queue order; `bd show <id>` gives blockers, comments and the lease.
2. `bd claim <id>` (or `bd claim --next`) claims atomically and prints a lease token. Keep it.
3. During long work, `bd heartbeat <id> --token <t>`. If it fails, stop: the claim was lost.
4. Finish with `bd close <id> --reason "what was done"` (add `--failed` if it failed), or give it back with `bd release <id>`.

## Recording work

- `bd create "Title" -d "why and what" --dep discovered-from:<id>` for work found along the way; `bd dep add <issue> <depends-on>` orders it.
- `bd comment add <id> "..."` leaves context for whoever picks an issue up; `bd remember "..."` stores a durable insight (`bd memories <query>` searches them).

## Working efficiently

- Keep output small: `bd ready --brief`, `bd list --brief` and `bd show <id> --brief` print only the key fields.
- When an issue is not ready or not where you expected, ask why: `bd ready --explain`, `bd show <id> --why`.
- Search with `bd query '<expr>'` instead of paging through lists, for example `bd query 'status = open AND label = x AND updated > 7d'`.
- Capture a quick follow-up with `bd q "title"`: it prints only the new id.
- Close a repeat with `bd duplicate <id> --of <other>`, and replaced work with `bd supersede <id> --with <newer>`, rather than closing it by hand: the link is kept.
- `bd epic status` shows each open epic's progress.
- `bd close <id> --reason "..." --claim-next` finishes an issue and claims the next ready one in one step.

## Feature specs

When `bd prime` shows a "Feature specs" section, the workspace keeps feature specs (experimental):

- Link every change you close to the spec or requirement it touches (`bd spec link <id> <spec or requirement>`), or mark it `bd spec none <id> -r '<why>'`.
- Keep requirements current: add one with `bd spec add <spec> --from <id> -- '<sentence>'` (`--non-goal` for a non-goal), replace a changed one with `bd spec change <req> --from <id> -- '<sentence>'`, and close one that no longer holds with `bd spec remove <req> -r '<why>'`. Options go before `--`: everything after it is the sentence.
- Create a new spec with `bd spec new <area> -- '<feature>'` (`--parent <spec>` for a sub-feature).
- `bd spec list`, `bd spec show <spec or area>` and `bd spec drift` show the specs and what drifted.
- `bd spec show <spec> --as-of <point>` shows a spec as it stood then, and `bd spec changes [<spec or area>] --since <point>` lists the requirements added, superseded, removed and edited since.
- `bd show <id>` and `bd claim <id>` list the specs governing an issue with their requirements, `bd close` hints on stderr when closed work is not linked, and `bd query 'spec = none'` / `bd query 'area = <name>'` find work by spec.

## Claims and take-overs

- Exit code 4 is a claim conflict: someone else holds it (possibly another session of your own actor), or it is not ready. Re-read with `bd show`; do not answer a 4 with `--take-over`, and `--force` never ends another actor's claim.
- After `/clear`, a resume or compaction, claims you took earlier may belong to another session of yours: `bd prime` lists them under "Held by other sessions of yours" with the command that takes each over (`bd update <id> --assignee <you> --take-over`, which prints the new lease token). Use `--take-over` only as `bd prime` or the subagent hook directs, and only for work this session is continuing; otherwise leave the claim to its holder.
- Exit code 13 is a stale `--if-revision`/`--if-status`/`--if-assignee` guard: re-read before retrying.
- In a remote workspace, 7 means the access token is missing or not allowed, 8 that the server is unreachable (safe to retry), and 9 that a write's answer was lost: check with `bd show` before running it again.

## Rules

- Use `--json` when parsing output.
- Close an issue only when its work is actually done.
- Never approve skill, MCP or playbook changes (`bd agents approve`) or copy skill or playbook files around approval (`.bd/approved/` is bd's): ask the user to review and approve them. In a remote workspace a server's playbook is found only once approved on this machine.
