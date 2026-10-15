# Agent work rubric

Version: 2

How well an agent did on a bd issue (or a playbook run and its steps), scored 1 to 5 on each dimension below, plus an overall score, and how hard the work was (Complexity, kept apart from the score). The `score-issue` workflow has a judge (`gpt-6-astra`) judge the work against this rubric and stores a draft, which becomes the score as it is or, when a person confirms scores (`score_confirm=person` on a `change` run, `confirm=person` on a `score` run), once they confirm or adjust it. Bump the version when an anchor changes meaning, so scores stay comparable.

## Scale

- **5**: what a strong engineer would hand in; nothing for a reviewer to fix. Rare.
- **4**: good; only minor or nit findings.
- **3**: acceptable; needed real rework in review, or has a gap a reviewer had to point out.
- **2**: poor; a requirement unmet, a defect shipped, or heavy rework by others.
- **1**: wrong, broken, or misleading.
- **null**: no evidence either way (say why). Never guess.

## Dimensions

### correctness

Does the change do what the requirements ask, without defects?

- 5: every requirement and acceptance criterion met; no defect found in review or since.
- 4: all met; only minor issues found.
- 3: met after a serious defect was fixed in review, or one requirement only partly met.
- 2: a requirement unmet, or a blocker/serious defect left in the result.
- 1: does not work, or solves a different problem.

### scope

Did it do exactly what was asked?

- 5: exactly the request; tempting extras filed as follow-ups, not done.
- 3: some unrequested edits or gold-plating, or a part silently left out.
- 1: large unrequested changes, or the request quietly narrowed.

### quality

Code quality and the project's conventions (AGENTS.md, and the project notes below).

- 5: idiomatic, minimal, readable; every convention followed.
- 3: works, but bends a convention, duplicates code, or is harder to read than needed.
- 1: hacks, suppressed warnings, disabled or weakened checks.

### verification

Is the work proven?

- 5: tests prove each requirement, including edge cases and the project's platform concerns; every gate green; the evidence is recorded.
- 3: happy path only, or a gate run but not recorded.
- 1: no tests for new behavior, or tests weakened to pass.

### process

bd discipline and honest reporting.

- 5: claimed under a lease; decisions, findings and follow-ups recorded in bd; closed with evidence; every summary, close reason and comment matches what the code and checks show.
- 3: gaps in the record (missing evidence, a follow-up left in chat), nothing misleading.
- 1: no tracking, or a claim that is false (says tests pass that fail, says done when not).

### autonomy

How much a person had to step in.

- 5: nothing beyond the approvals the process asks for.
- 4: one clarification.
- 3: a correction or a re-run.
- 2: several interventions, or escalated what it could have handled.
- 1: a person had to redo the work.

Escalating real ambiguity or a real conflict is the right call: do not count it against autonomy.

## Overall

A judgment, not the mean. Correctness weighs most; process and autonomy least. Two caps:

- overall is at most correctness;
- any dimension at 1 caps overall at 2.

## Complexity

How hard the work was, whoever did it and however it went. It is not a dimension: it stays out of overall and the caps, so a 3 on hard work reads differently from a 3 on easy work. Score it from the task and the change, citing the factors that drive it:

- **size**: files, lines, crates and modules touched;
- **ambiguity**: how much the requirements left to decide;
- **novelty**: a known pattern in this codebase, or new ground (an undocumented API, a new convention);
- **risk**: what breaks if it is wrong (commands and their output, the wire protocol, stored data, security, CI and releases);
- **breadth**: how many parts must change together and stay consistent.

Anchors:

- 5: novel design across many parts, high risk, or research needed before it could be built.
- 4: hard; cross-cutting, ambiguous or platform-dependent, several interacting parts, real regression risk.
- 3: moderate; several files or a non-obvious approach, real decisions, tests beyond the happy path.
- 2: simple; a small change in one place with clear requirements and a known pattern.
- 1: trivial; mechanical or a one-line fix, no decisions.

The agent estimates it first thing at the requirements step, from the task alone and before reading code or investigating, as the run's `complexity_estimate` metadata: `{"rubric": 2, "score": 3, "factors": "size: ...; novelty: ...", "by": "<actor>"}`. The judge scores it at the end; `score-issue` shows it the issue without the estimate (nor the work trace or earlier scores) and tells it not to look them up. The comment gives the gap (judged minus estimate). A large gap is worth reading: underestimated work tends to explain rework.

## Judging

- Score from evidence: the issue and its children, comments, history, close reasons, the diff and the checks. Verify an agent's own claims (summaries, "tests pass") against the code before crediting them.
- Who or which model did the work does not change the score; neither does how long the write-up is. Don't look at the `complexity_estimate`, `work`, `score` or `score_judge` metadata while scoring.
- Cite evidence for every score (file:line, commit, comment, event). Use null where there is none.
- Confidence is low when the change could not be found or the evidence is thin.

## Recording

Scores live in the scored issue's metadata (for a playbook run, the run issue), as JSON:

```json
{
	"rubric": 2,
	"overall": 4,
	"dims": {
		"correctness": 4,
		"scope": 5,
		"quality": 4,
		"verification": 3,
		"process": 4,
		"autonomy": 5
	},
	"complexity": 3,
	"by": "..."
}
```

- `score_judge`: the judge's draft (`by` is the judge model, `gpt-6-astra`, plus `confidence`); the workflow also comments its reasoning on the issue, with the complexity gap and a summary of the work trace.
- `score`: the confirmed score. By default the judge's draft is accepted as it is: copied without `confidence`, with `by` set to `judge`. A person may set it instead, behind a human gate when the run asks for one, or later over an accepted draft. To agree, copy the draft with `by` set to the person; to adjust, change the numbers and comment why, starting the comment with `Score adjusted:` (the judge is not shown it on a rerun):

  ```bash
  bd update <issue> --set-metadata 'score={"rubric":2,"overall":4,"dims":{...},"complexity":3,"by":"Quang Le"}'
  ```

- `complexity_estimate`: the agent's estimate from the requirements step (Complexity).
- `work`: who did what, written by `.github/scripts/trace-run.mjs` when the run is scored. Per step of the run: each agent (the session's main thread, a subagent, a workflow agent) with its model, effort, requests, tokens and times, including its active span (first request to the end of its last, approximate), plus totals per model and effort, and a `timing` block (each step's elapsed time from its claim or the previous step's close, gate waits, and human wait). It comes from the Copilot CLI session logs (`~/.copilot/session-state`) on the machine that scores, so sessions run elsewhere are listed as missing; each request carries its AI credits (1 credit = $0.01), and a request logged without them counts as unpriced. It holds no transcript content (prompts, tool output, thinking), but it does store each agent's label: a subagent's type and description, or a workflow's agent label, cut to 80 characters, so keep secrets out of those. Run it by hand for an older run: `node .github/scripts/trace-run.mjs <run> --summary` (add `--write` to store it).

The gap between `score_judge` and a person's `score` (one whose `by` is not `judge`) over many issues shows how far the judge can be trusted. Read scores next to `complexity` and `work`: which model and effort did which kind of work, and how it went. `node .github/scripts/calibrate.mjs` joins them across every run, with cost and time.

## Project notes: bd-sync

- quality: AGENTS.md Conventions & Patterns: mutations only through `Store::write` with events in the same transaction, `graph::recompute` seeds, the lease invariant, `check_claim_override` before any force refusal, `Policy` checks, I/O only through `io.rs`, minimal indexes, fixed query plans for walks.
- verification: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`; Linux, macOS and Windows must all build (cfg-gated paths); unit tests in the crate, end-to-end ones in `crates/bd/tests/`.
- scope and quality: the `docs/` or CONTRIBUTING.md page a change affects is updated; agent assets (skills, MCP definitions) are never changed without the user's approval.
