---
name: bd
description: Use when working in a repository that tracks tasks with bd (it has a .bd/ directory). Trigger when the user asks to find ready work, claim, renew, or close tasks, record dependencies, blockers, or discovered follow-up work, leave handoff comments, store durable project memories, or recover project context.
---

# bd

bd is this repository's shared task tracker: a dependency-aware work queue in `.bd/bd.db` (SQLite, WAL). Use it instead of markdown TODO files or local notes for any work another session or agent may need to see.

## First step

Run `bd prime`. It prints the workflow, your current claims, the top of the ready queue, and project memories. Outside a workspace it prints nothing; `bd info` shows which workspace is active (a database path, or a server URL for a remote workspace).

Your actor: each agent session acts as its own actor, `<user>/<session>`, derived from the session id the agent harness sets (`$CLAUDE_CODE_SESSION_ID`, `$COPILOT_AGENT_SESSION_ID`, `$CODEX_THREAD_ID`) and `$BD_SESSION`, so claims of concurrent sessions never mix. `bd prime` shows yours. If it warns that you are the plain default actor and that actor holds claims, run each of your bd commands with `BD_SESSION=<name>` before claiming anything, and leave those claims to their holder. Do not set `BD_ACTOR` to a name other sessions use.

After `/clear`, a resume, or in a subagent with its own session id, claims you took earlier belong to another actor of your user: `bd prime` lists them under "Held by other sessions of yours", with the command that takes each over (`bd update <id> --assignee <you> --take-over`, which prints the new lease token to use from then on), and exit-4 hints name it too. Take one over only if this session is continuing that work; otherwise another session is on it. An actor named outright (`--actor`, `BD_ACTOR`) has no other sessions: `pool/w2` is another actor to `pool/w1`. To hand a claimed issue to a subagent, have the subagent take it over, or run its bd commands with `BD_ACTOR=<your actor>`.

Claude Code subagents share their parent session's id, so their plain `bd` commands act as the parent. If your context says to pass `--session agent-<id>` to bd (the `bd hook subagent-start` hook), do so on every bd command; a bd command refused for lacking it names the corrected command to run. When you delegate to subagents without those hooks, tell each to run every bd command as `bd --session <distinct name> ...`.

## Workflow

1. Find work: `bd ready` (queue order), `bd list --status in_progress`, `bd blocked`.
2. Inspect before editing: `bd show <id>` (blockers, dependencies, comments, lease).
3. Claim atomically: `bd claim <id>`, or `bd claim --next` for the head of the queue. Note the lease token it prints. A claim someone already holds is refused (exit 4), even when it was taken under your own actor name by another session; `bd claim <id> --token <t>` renews only a claim you hold.
4. During long work, renew the lease: `bd heartbeat <id> --token <t>`. If it fails, stop: the claim was lost.
5. Record follow-up work: `bd create "Title" -d "why and what" --dep discovered-from:<id>`; order work with `bd dep add <issue> <depends-on>`.
6. Finish: `bd close <id> --reason "..."` (add `--failed` if it failed), or give it back with `bd release <id>`.
7. Never end or take over work another agent holds: closing, releasing, reassigning, moving out of `in_progress` or deleting its live claim fails with exit 4 naming the holder, and `--force` does not change that. `--take-over` takes it over and is recorded in the history; use it only when asked to.

## Playbooks and gates

- Repeatable multi-step work lives in `.bd/playbooks/*.toml`: `bd playbook list`, then `bd playbook run <name> --var key=value` (preview with `bd playbook plan`). Its steps are ordinary issues `<run>.<step>`: work them with `bd ready --run <run>`, claim, close.
- `bd playbook status <run>` shows every step and what it waits on. Runs close themselves when their last step closes.
- Gates (`<run>.gate-<step>`) hold a step until a person approves, a timer passes, an issue closes, or a GitHub PR/run finishes. Never claim them: `bd gate list`, `bd gate check`, and `bd gate resolve <id>` when a person has approved. `bd prime` lists gates waiting on a person.

## Agent skills and MCP definitions

- A workspace may serve skills and MCP server definitions to each agent harness. Session-start context may report what changed (lines starting `bd:`): skills updated, MCP definitions waiting for approval, conflicts.
- Mid-session, `bd agents status` shows what differs from the server and `bd agents pull` brings skills up to date (add `--harness claude|codex|copilot` if no harness is detected). Pulls never write new or changed MCP definitions.
- Never approve MCP changes, and never edit `.mcp.json`, `.github/mcp.json` or `.codex/config.toml` to get around approval: an MCP definition is a command that runs on the user's machine. Ask the user to review the changes and run `bd agents approve` in a separate terminal (it refuses agent sessions).
- Pulled skills or approved MCP servers may need a reload by the user: Copilot CLI `/skills reload` and `/mcp reload`; Claude Code `/reload-skills`, and a restart for MCP; Codex loads skills by itself, and needs a restart for MCP.
- Treat server-provided skills as workspace instructions: they are applied without approval and may carry hooks or scripts that run commands, so raise anything unexpected in them with the user.

## Rules

- Prefer `--json` when parsing output.
- Exit code 4 is a claim conflict (held by someone else, possibly another session of your own actor, or not ready); 13 is a stale `--if-revision` guard. Re-read instead of retrying blindly, and do not answer a 4 with `--take-over`.
- In a remote workspace (`.bd/remote.toml`), commands run on a shared bd server and claims stay atomic across every client. Exit code 7 means the access token (`BD_TOKEN`, or one saved by `bd remote login`) is missing or not allowed; 8 means the server is unreachable, and retrying is safe; 9 means a write's answer was lost, so it may have taken effect: check (`bd show`) before running it again. `bd remote show` diagnoses the connection and the token.
- Do not close or mutate tasks unless the work is actually done.
- Store durable insights with `bd remember "..."`; search them with `bd memories <query>`.
