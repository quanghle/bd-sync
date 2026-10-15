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

## Copilot coding agent (github.com)

A coding agent session gets bd from `.github/workflows/copilot-setup-steps.yml`, with `BD_REMOTE` and `BD_TOKEN` from the repository's `copilot` environment. No session hook runs, so:

- Start with `bd prime`. If it fails, run `bd remote show` and say in the pull request that bd was unreachable or refused the token; don't recreate a local database.
- If `bd prime` warns that you are the plain default actor, run every bd command as `BD_SESSION=<your branch name> bd ...`.
- The GitHub issue you were assigned names its bd issue in a hidden `<!-- bd:<id> -->` line at the end of its body (`bd github push --create` writes it), or in its text. Use that id: `bd show <id>`, then claim it.
- If the GitHub issue names no bd issue, don't create one (a later `bd github pull` would import the GitHub issue as a second bd issue): say so in the pull request, and the maintainer links it.
- Claim with a lease that outlasts builds and test runs: `bd claim <id> --ttl 60m`, and keep the printed token. Renew with `bd heartbeat <id> --token <t> --ttl 60m` before long steps (`cargo test --workspace` takes a while); if a heartbeat fails, stop: the claim is gone.
- Put the bd issue id in the pull request title or description and in commit messages, as this repository's commits do (`... (bd-xxxx)`).
- You may commit and push to your own branch for the pull request; that is the exception to "do not commit or push". Never push to `main` or to another branch.
- When the pull request is ready for review, close the issue with `bd close <id> --token <t> --reason "PR #<n>: what was done"`, or `bd release <id> --token <t>` with a `bd comment add` if you stopped short.
