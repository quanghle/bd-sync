// Copilot CLI port of .claude/workflows/score-issue.js: a judge scores how well an agent did on a bd issue (or a
// playbook run) against .bd/rubric.md and stores a draft for a person to confirm.
import { defineWorkflow, joinSession } from "@github/copilot-sdk/extension";

// ---------- judge ----------
// A Copilot model id at the strongest reasoning it offers. Fable is Claude Code only, so a score's `by` names this model.
const JUDGE = { model: "gpt-6-astra", effort: "xhigh" };
const DIMS = ["correctness", "scope", "quality", "verification", "process", "autonomy"];

// ---------- schemas ----------
const SETUP = {
    type: "object",
    properties: {
        root: { type: "string", description: "absolute path of the main checkout" },
        rubric: { type: "integer", description: 'the number on the "Version:" line of .bd/rubric.md' },
        estimate: { type: ["integer", "null"], description: "the issue's complexity_estimate.score metadata, or null if it has none" },
        error: { type: "string" },
    },
    required: ["root"],
};
const DIM = {
    type: "object",
    properties: {
        score: { type: ["integer", "null"], minimum: 1, maximum: 5, description: "null when there is no evidence either way" },
        evidence: { type: "string", description: "what the score rests on: file:line, commit, comment, event; for null, why there is none" },
    },
    required: ["score", "evidence"],
};
const SCORE = {
    type: "object",
    properties: {
        dims: { type: "object", properties: Object.fromEntries(DIMS.map((d) => [d, DIM])), required: DIMS },
        overall: { type: "integer", minimum: 1, maximum: 5 },
        complexity: { ...DIM, description: "how hard the work was (the rubric's Complexity section): size, ambiguity, novelty, risk, breadth" },
        confidence: { type: "string", enum: ["high", "low"], description: "low when the change could not be found or the evidence is thin" },
        summary: { type: "string", description: "two or three sentences: how the work went" },
        strengths: { type: "array", items: { type: "string" } },
        problems: {
            type: "array",
            items: {
                type: "object",
                properties: { dimension: { type: "string" }, problem: { type: "string" }, evidence: { type: "string" } },
                required: ["dimension", "problem", "evidence"],
            },
        },
        change: { type: "string", description: "the commits, range or worktree diff judged" },
    },
    required: ["dims", "overall", "complexity", "confidence", "summary", "change"],
};
const TRACED = {
    type: "object",
    properties: { ok: { type: "boolean" }, summary: { type: "string", description: "the command output, verbatim" }, error: { type: "string" } },
    required: ["ok"],
};
const RECORDED = {
    type: "object",
    properties: { ok: { type: "boolean" }, error: { type: "string" } },
    required: ["ok"],
};

// A plan-implement-review result, reduced to what bears on the score.
const fmtResult = (r) => {
    if (!r || typeof r !== "object") return "";
    const n = (k) => (Array.isArray(r[k]) ? r[k].length : undefined);
    return JSON.stringify(
        {
            status: r.status,
            reason: r.reason,
            concern: r.concern,
            rounds: r.rounds,
            openCounts: r.openCounts,
            approved: n("approved"),
            rejected: n("rejected"),
            nonBlocking: n("nonBlocking"),
            dropped: n("dropped"),
            amended: n("amended"),
            unvalidated: n("unvalidated"),
            gateFailures: Array.isArray(r.failures) ? r.failures.map((f) => f.command) : undefined,
            stillOpen: Array.isArray(r.open) ? r.open.map((f) => `${f.id} ${f.severity} ${f.file}: ${f.claim}`) : undefined,
            deviations: Array.isArray(r.done) ? r.done.filter((d) => d.deviations).map((d) => `${d.id}: ${d.deviations}`) : undefined,
        },
        null,
        2,
    );
};

async function run(ctx) {
    const args = ctx.args;
    const A = typeof args === "string" ? { issue: args } : { ...args };
    if (!A.issue || typeof A.issue !== "string") throw new Error("args.issue is required (the bd issue or playbook run to score)");
    const { log, phase } = ctx;

    // `kind` picks the built-in agent. Mechanical agents (setup, trace, record) only run commands and report output: the task agent at low effort.
    const agent = (prompt, { label, kind = "task", effort, model, schema }) =>
        ctx.agent(prompt, { label, agent: kind, schema, ...(model ? { model } : {}), ...(effort ? { reasoningEffort: effort } : {}) });

    // ---------- Setup ----------
    phase("Setup");
    const where = A.workdir || ".";
    const setup = await agent(
        `In ${where}, run: dirname "$(git rev-parse --path-format=absolute --git-common-dir)" and return its output as root. ` +
            `Then read the "Version:" line of <root>/.bd/rubric.md and return its number as rubric. ` +
            `Then run \`bd -C <root> show ${A.issue} --json\` and return its metadata.complexity_estimate.score as estimate (null if absent). ` +
            `If the rubric file is missing, return root and set error. Do nothing else.`,
        { label: "setup", effort: "low", schema: SETUP },
    );
    if (!setup?.root) return { status: "failed", reason: "could not find the main checkout" };
    if (setup.error || !Number.isInteger(setup.rubric)) {
        return { status: "failed", reason: `no usable rubric at ${setup.root}/.bd/rubric.md: ${setup.error || "no version"}` };
    }
    const ROOT = setup.root;
    const bd = `bd -C ${ROOT}`;
    const actorFlag = A.actor ? ` --actor "${A.actor}"` : "";

    // ---------- Judge ----------
    phase("Judge");
    const change = A.range
        ? `The change is the git range ${A.range}: \`git -C ${A.workdir || ROOT} log --stat ${A.range}\` and \`git -C ${A.workdir || ROOT} diff ${A.range}\`.`
        : A.workdir
          ? `The change is in the worktree ${A.workdir}, committed or not: \`git -C ${A.workdir} diff ${A.base || "main"}\` (plus untracked files from \`git -C ${A.workdir} status\`).`
          : `Find the change: commits named in the close reasons and comments of the issue and its children; else \`git -C ${ROOT} log --all --grep=${A.issue}\`. ` +
            `If none can be found, score what the bd record shows, use null where the code is needed, and set confidence low.`;
    const judged = await agent(
        `You are the judge. Score how well the agent work on bd issue ${A.issue} went, against the rubric at ${ROOT}/.bd/rubric.md. ` +
            `Read the whole rubric first, including its Judging section and the project notes, and hold every score to its anchors.\n\n` +
            `Gather the evidence yourself. You are read-only: do not edit files, commit, or write to bd (no create, update, comment, close). ` +
            `You may run read-only commands, and a targeted test or check when needed to confirm or refute a specific claim.\n` +
            `- Read the issue only through this view, which leaves out the complexity estimate, the work trace and earlier scores so they cannot sway you: ` +
            `\`${bd} show ${A.issue} --json | jq 'del(.metadata.complexity_estimate, .metadata.work, .metadata.score, .metadata.score_judge)'\` ` +
            `(description, acceptance, design, notes, metadata). Read its comments and history the same way, without earlier judges' comments ` +
            `and people's score adjustments (they carry the earlier score, the estimate's gap and the trace): \`${bd} comments ${A.issue} --json | jq 'map(select(.text | test("^(Judge.s score|Score adjusted)") | not))'\` ` +
            `and \`${bd} history ${A.issue} | grep -Ev "Judge.s score|Score adjusted"\` (as text: its JSON and --diff carry the metadata values).\n` +
            `- If it has children (a playbook run's steps, an epic's tasks, review findings filed as bugs), read each the same way: their evidence, close reasons and findings are the record of the work.\n` +
            `  Skip the children that hold an earlier scoring (ids ending in .score, .score-confirm or .gate-score-confirm): their close reasons carry its result.\n` +
            `- ${change} Read the surrounding code where the diff alone does not tell.\n` +
            (A.result ? `- The implementing workflow's result:\n${fmtResult(A.result)}\n` : "") +
            (A.context ? `- Notes from the caller (a person's account of what happened counts as evidence):\n${A.context}\n` : "") +
            `Do not look up the complexity_estimate, work, score or score_judge metadata by other means: score from the work itself.\n` +
            `\nScore each dimension (${DIMS.join(", ")}) from 1 to 5, or null with the reason when there is no evidence either way, and cite the evidence for each. ` +
            `Verify the agent's own claims (summaries, "tests pass", "done") against the code and the record before crediting them; a false claim is a process problem. ` +
            `Who or which model did the work does not change a score. Then give overall, applying the rubric's caps, ` +
            `complexity (the rubric's Complexity section, outside overall: how hard the work was, not how well it went), a short summary, strengths, problems ` +
            `(each with its dimension and evidence), the change you judged, and confidence.`,
        { label: "judge", kind: "general-purpose", ...JUDGE, schema: SCORE },
    );
    if (!judged) return { status: "failed", reason: "the judge failed", issue: A.issue };
    const valid = (s) => s === null || (Number.isInteger(s) && s >= 1 && s <= 5);
    const bad = [...DIMS.filter((d) => !valid(judged.dims?.[d]?.score)), ...(valid(judged.complexity?.score) ? [] : ["complexity"])];
    if (bad.length || !Number.isInteger(judged.overall)) {
        return { status: "failed", reason: `the judge returned an unusable score (${bad.join(", ") || "overall"})`, issue: A.issue, judged };
    }

    // The rubric's caps, enforced here so the stored score always obeys them.
    const scores = Object.fromEntries(DIMS.map((d) => [d, judged.dims[d].score]));
    let overall = judged.overall;
    const caps = [];
    if (scores.correctness != null && overall > scores.correctness) {
        overall = scores.correctness;
        caps.push(`at most correctness (${scores.correctness})`);
    }
    if (DIMS.some((d) => scores[d] === 1) && overall > 2) {
        overall = 2;
        caps.push("a dimension at 1 caps it at 2");
    }
    if (caps.length) log(`Overall ${judged.overall} capped to ${overall}: ${caps.join("; ")}`);
    const complexity = judged.complexity.score;
    const score = { rubric: setup.rubric, overall, dims: scores, complexity, confidence: judged.confidence, by: JUDGE.model };
    log(`${A.issue}: overall ${overall} (${DIMS.map((d) => `${d} ${scores[d] ?? "-"}`).join(", ")}), complexity ${complexity ?? "-"}, confidence ${judged.confidence}`);
    const estimate = Number.isInteger(setup.estimate) ? setup.estimate : null;
    const gap =
        estimate == null
            ? "no estimate was recorded"
            : complexity == null
              ? `estimated ${estimate}`
              : `estimated ${estimate}, gap ${complexity - estimate > 0 ? "+" : ""}${complexity - estimate}`;

    // ---------- Trace ----------
    // After the judge, which is shown neither the trace nor the estimate. A failed trace is reported, never fails the scoring.
    phase("Trace");
    const traced = await agent(
        `Run exactly: node ${ROOT}/.github/scripts/trace-run.mjs ${A.issue} --root ${ROOT} --summary` +
            `${A.dryRun ? "" : " --write"}${A.actor ? ` --actor "${A.actor}"` : ""}\n` +
            `Return its standard output, verbatim, as summary, even when it exits with an error; ok=true if it exited 0, ` +
            `otherwise ok=false and its standard error as error. Do nothing else.`,
        { label: "trace", effort: "low", schema: TRACED },
    );
    const traceText = traced?.summary?.trim();
    const work = traceText
        ? traceText + (traced.ok ? "" : `\n(Not stored as work metadata: ${traced.error || "the write failed"})`)
        : `Work trace failed: ${traced ? traced.error || "no output" : "trace agent failed"}`;
    log(work.split("\n")[0]);
    if (A.dryRun) return { status: "scored", recorded: false, issue: A.issue, score, judged, caps, work };

    // ---------- Record ----------
    phase("Record");
    const comment = [
        `Judge's score (rubric v${setup.rubric}, ${JUDGE.model}): overall ${overall}/5, confidence ${judged.confidence}` +
            (caps.length ? ` (judge said ${judged.overall}; capped: ${caps.join("; ")})` : ""),
        `Judged: ${judged.change}`,
        "",
        judged.summary,
        "",
        ...DIMS.map((d) => `- ${d}: ${scores[d] ?? "n/a"}. ${judged.dims[d].evidence}`),
        "",
        `Complexity: ${complexity == null ? "n/a" : `${complexity}/5`} (${gap}). ${judged.complexity.evidence}`,
        ...(judged.strengths?.length ? ["", "Strengths:", ...judged.strengths.map((s) => `- ${s}`)] : []),
        ...(judged.problems?.length ? ["", "Problems:", ...judged.problems.map((p) => `- [${p.dimension}] ${p.problem} (${p.evidence})`)] : []),
        "",
        work,
        "",
        "Draft: accepted as the score metadata, or confirmed or adjusted by a person when the run asks for one (.bd/rubric.md, Recording).",
    ].join("\n");
    const rec = await agent(
        `Record a score in bd. Run these two commands, in order, exactly as given except that <Text> is the "Text" under it, ` +
            `passed verbatim as one shell argument (use a quoted heredoc, e.g. "$(cat <<'EOF' ... EOF)", so quotes and backticks survive). Do nothing else.\n\n` +
            `1. ${bd} update ${A.issue} --set-metadata 'score_judge=${JSON.stringify(score)}'${actorFlag}\n\n` +
            `2. ${bd} comment add ${A.issue} <Text>${actorFlag}\n  Text:\n${comment}\n\n` +
            `Return ok=true if both succeeded; otherwise ok=false and the error.`,
        { label: "record", effort: "low", schema: RECORDED },
    );
    if (!rec?.ok) {
        return { status: "scored", recorded: false, reason: `could not record: ${rec ? rec.error : "record agent failed"}`, issue: A.issue, score, judged, caps, work };
    }
    return { status: "scored", recorded: true, issue: A.issue, score, judged, caps, work };
}

const scoreIssue = defineWorkflow({
    meta: {
        name: "score-issue",
        description:
            `A judge (${JUDGE.model}, ${JUDGE.effort} effort) scores how well an agent did on a bd issue (or playbook run) against the rubric in .bd/rubric.md ` +
            "and stores a draft score, for the playbook to accept or a person to confirm. Use for scoring finished agent work on a bd issue, epic or playbook run, e.g. from a playbook's score step. " +
            "args: { issue, range?, workdir?, base?, result?, context?, actor?, dryRun? }. The judge reads the rubric, the issue and its children, comments, history " +
            "and the change, and scores each dimension with evidence, plus the work's complexity (kept out of overall). Then .github/scripts/trace-run.mjs traces " +
            "which agents did each step with which model and effort, and for how long, from the Copilot CLI sessions on this machine (after the judge, which is shown " +
            "neither the trace nor the estimate), into the issue's work metadata. range is the git revision range of the change (e.g. main..my-branch); without it the " +
            "judge finds the commits named in close reasons and comments, or by `git log --all --grep=<issue>`. workdir (with base, default main) points at uncommitted " +
            "work in a worktree. result is a plan-implement-review result, summarized as evidence; context is free text from the caller (e.g. what a person had to " +
            "correct). The draft goes into the issue's score_judge metadata (rubric version, overall, dims, complexity, confidence, by: the judge model) and the " +
            "reasoning, the complexity estimate's gap and the trace summary into a comment on the issue, written as actor (pass your bd actor); the playbook then accepts it, or a person " +
            "sets the score metadata (.bd/rubric.md, Recording). dryRun returns the score and trace summary without writing to bd.",
        phases: [
            { title: "Setup", detail: "find the main checkout and the rubric version" },
            { title: "Judge", detail: "the judge scores the work against the rubric, with evidence" },
            { title: "Trace", detail: "which agents did each step, with which model and effort, and for how long (trace-run.mjs)" },
            { title: "Record", detail: "score_judge metadata and a reasoning comment on the issue" },
        ],
        argsSchema: {
            type: "object",
            properties: {
                issue: { type: "string" },
                range: { type: "string" },
                workdir: { type: "string" },
                base: { type: "string" },
                result: { type: "object" },
                context: { type: "string" },
                actor: { type: "string" },
                dryRun: { type: "boolean" },
            },
            required: ["issue"],
        },
    },
    run: async (ctx) => JSON.parse(JSON.stringify((await run(ctx)) ?? null)),
});

await joinSession({ workflows: [scoreIssue] });
