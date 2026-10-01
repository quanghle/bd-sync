# GitHub Copilot Instructions

This repository tracks its work with **bd**, the Rust coordination engine built here (`.bd/bd.db`). AGENTS.md has the full workflow.

- Run `bd prime` for context: your claims, ready work, project memories.
- Loop: `bd ready` → `bd claim <id>` (or `bd claim --next`) → work → `bd close <id> --reason "..."`.
- Record discovered work with `bd create "..." --dep discovered-from:<id>`, ordering with `bd dep add <issue> <depends-on>`, durable insights with `bd remember "..."`.
- Use bd for all task tracking; no markdown TODO lists.
- Do not commit or push unless explicitly asked.
