# GitHub Copilot Instructions

This repository tracks its work with **bd**, the Rust coordination engine built here. Issues live on the bd server `https://bd.quangle.net/w/bd-sync` (`.bd/remote.toml`), never in a local database or JSONL. AGENTS.md has the full workflow.

- Run `bd prime` for context: your actor, claims, ready work, project memories.
- Each session acts as its own actor (`<user>/copilot-<id>`, from `$COPILOT_AGENT_SESSION_ID`); don't set `BD_ACTOR` to a shared name. If `bd prime` warns that you are the plain default actor, run your bd commands with `BD_SESSION=<name>`.
- Claims from an earlier session of yours (before `/clear` or a resume, or a parent agent's) are listed by `bd prime` under "Held by other sessions of yours" with their takeover command; run it only if this session is continuing that work.
- Loop: `bd ready` → `bd claim <id>` (or `bd claim --next`) → work → `bd close <id> --reason "..."`.
- Exit code 4 means someone else holds the claim (maybe another session of yours): pick other work. `--force` does not override a claim; never pass `--take-over` unless asked (it is recorded). Exit 7 is a missing or refused token, 8 an unreachable server: report it rather than working around bd.
- Record discovered work with `bd create "..." --dep discovered-from:<id>`, ordering with `bd dep add <issue> <depends-on>`, durable insights with `bd remember "..."`.
- Use bd for all task tracking; no markdown TODO lists.
- Do not commit or push unless explicitly asked.

## Changes

AGENTS.md (Changes, Scoring agent work, Delegating to agents) has the details; in short:

- Run each change through the `change` playbook: `bd playbook run change --var task="..." --var tier=<small|standard|critical>`, optionally `--parent <issue>`. Work its steps in order and close each with the evidence its acceptance criteria name; record decisions in bd (the step's design field or `decision` issues under it), not in repo files. Human gates are a person's: never `bd gate resolve` one yourself.
- At the requirements step, before investigating, set the run's `complexity_estimate` metadata from the task alone (`.bd/rubric.md`, Complexity).
- For implement, verify and review, use the `plan-implement-review` workflow (the Copilot CLI extension in `.github/extensions/plan-implement-review/`) with `reviewStep` = the run's review step and the run's `tier`. Close the `confirmedFixes` it returns (and the `dropped` findings with a `bdId`, as not a defect) once implement and verify are closed. Its gate is CI's: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`.
- The score step runs the `score-issue` workflow (the Copilot CLI extension in `.github/extensions/score-issue/`; its judge is `gpt-6-astra`, not you): pass `issue` = the run, `actor` = your bd actor, and `range`, `result` and `context` as the step says. Write the `score` metadata only at the run's accept step (`score_confirm=judge`, the default), as the judge's draft with `by` set to `judge`; with `score_confirm=person` a person confirms it.
- The last step, recalibration check, runs `node .github/scripts/recalibrate-due.mjs --start --actor <you>`: at 10 confirmed scores (accepted or a person's) not yet covered it starts the `recalibrate` playbook (report, propose, human approval, apply). Never resolve its approval gate.
- When delegating to subagents, match the agent to the task: the light `task` agent for running commands and reporting output, `general-purpose` for code; escalate a level when a cheaper run fails rather than retrying at the same one.

## Copilot coding agent (github.com)

A coding agent session gets bd from `.github/workflows/copilot-setup-steps.yml`, with `BD_REMOTE` and `BD_TOKEN` from the repository's `copilot` environment. No session hook runs, so:

- Start with `bd prime`. If it fails, run `bd remote show` and say in the pull request that bd was unreachable or refused the token; don't recreate a local database.
- If `bd prime` warns that you are the plain default actor, run every bd command as `BD_SESSION=<your branch name> bd ...`.
- The GitHub issue you were assigned names its bd issue in a hidden `<!-- bd:<id> -->` line at the end of its body (`bd github push --create` writes it), or in its text; without either, `bd query 'external_ref = gh:owner/name#N'` (the repository lowercased; `gh:host/owner/name#N` off github.com) finds the bd issue linked to it. Use that id: `bd show <id>`, then claim it.
- If the bd issue is a step of a `change` run (its parent has `metadata.playbook.role = run`), work that step and its siblings as the playbook describes, with the `plan-implement-review` workflow if this session offers it; otherwise implement the issue directly and run the CI gates above before opening the pull request. Don't start a `change` run yourself.
- If the GitHub issue names no bd issue, don't create one (a later `bd github pull` would import the GitHub issue as a second bd issue): say so in the pull request, and the maintainer links it.
- Claim with a lease that outlasts builds and test runs: `bd claim <id> --ttl 60m`, and keep the printed token. Renew with `bd heartbeat <id> --token <t> --ttl 60m` before long steps (`cargo test --workspace` takes a while); if a heartbeat fails, stop: the claim is gone.
- Put the bd issue id in the pull request title or description and in commit messages, as this repository's commits do (`... (bd-xxxx)`).
- You may commit and push to your own branch for the pull request; that is the exception to "do not commit or push". Never push to `main` or to another branch.
- When the pull request is ready for review, close the issue with `bd close <id> --token <t> --reason "PR #<n>: what was done"`, or `bd release <id> --token <t>` with a `bd comment add` if you stopped short.
