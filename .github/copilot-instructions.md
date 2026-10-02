# GitHub Copilot Instructions

This repository tracks its work with **bd**, the Rust coordination engine built here (`.bd/bd.db`). AGENTS.md has the full workflow.

- Run `bd prime` for context: your actor, claims, ready work, project memories.
- Each session acts as its own actor (`<user>/copilot-<id>`, from `$COPILOT_AGENT_SESSION_ID`); don't set `BD_ACTOR` to a shared name. If `bd prime` warns that you are the plain default actor, run your bd commands with `BD_SESSION=<name>`.
- Loop: `bd ready` → `bd claim <id>` (or `bd claim --next`) → work → `bd close <id> --reason "..."`.
- Exit code 4 means someone else holds the claim (maybe another session of yours): pick other work. `--force` does not override a claim; never pass `--take-over` unless asked (it is recorded).
- Record discovered work with `bd create "..." --dep discovered-from:<id>`, ordering with `bd dep add <issue> <depends-on>`, durable insights with `bd remember "..."`.
- Use bd for all task tracking; no markdown TODO lists.
- Do not commit or push unless explicitly asked.
