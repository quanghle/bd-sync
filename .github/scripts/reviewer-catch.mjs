#!/usr/bin/env node
// How often each reviewer model and effort catches what a paired pass over the same diff and prompt found, by the
// complexity band of the bd run it reviewed and the rubric version that band was scored under: the evidence for which
// model and effort the reviewer roles get.
//
//   node .github/scripts/reviewer-catch.mjs [--root <checkout>] [--sessions <dir>] [--projects <dir>] [--json]
//
// Reads three sources on this machine, and `bd show` / `bd list` for complexity. Read-only: it writes no file and
// nothing to bd.
//
// 1. Copilot CLI sessions (<sessions>/<session>/, default ~/.copilot/session-state): the review and validate agents
//    the plan-implement-review extension recorded in files/workflow-agents/<run id>.jsonl (a { type: 'run' } header,
//    then one { type: 'agent', label, model, effort, prompt_sha256, result, finding? } line per agent), and
//    events.jsonl for the model and reasoning effort each agent actually ran with. Copilot keeps neither a workflow
//    agent's prompt nor its result, which is why the extension records them.
// 2. Claude Code workflow journals (<projects>/<encoded checkout or its .claude/worktrees/*>/<session>/subagents/
//    workflows/<wf>/journal.jsonl, default ~/.claude/projects): 'started' entries { agentId, label } and 'result'
//    entries { agentId, key, result } (an object or a JSON string), each agent's agent-<id>.meta.json and transcript
//    agent-<id>.jsonl beside them, and the workflow's run record <session>/workflows/<wf>.json ({ workflowName, args }).
// 3. Review passes run as plain Claude Code subagents (hand-run: <session>/subagents/agent-<id>.meta.json and .jsonl,
//    outside workflows/), `git log -1 --format=%s <sha>` for the subject of a commit a hand-run review names, and
//    `bd list --parent <run>.review --all` for the Finding bugs filed under a change run's review step.
//
// Passes. A review agent labelled review:<kind>:r<N> is a real pass, review:<kind>:r<N>@shadow:<model>-<effort> a
// shadow (plan-implement-review's shadowReview); any other suffix (an escalated retry) is not a pass. A Copilot pass's
// model and effort come from the session's subagent events, else what the workflow asked for; a Claude Code pass's from
// its meta, else its transcript's requests (a versioned id wins over an alias). A shadow falls back to its label. What
// can't be read is 'unknown', never guessed. A pass without a result failed and is never paired.
//
// Models. Every model is named by its id in Copilot's form: Claude Code's claude-opus-5-5 (or a dated or [1m] variant)
// is written claude-opus-5.5, so cells from both harnesses for the same model and effort are one cell. A model known
// only by its alias (opus, sonnet) stays as the alias, apart from the versioned id. Other ids (gpt-6-astra) are kept.
//
// Prompt. A Copilot agent's prompt is the hash the extension recorded. A Claude Code workflow agent's is its computed
// task: the leading user entry (before the first assistant entry) that starts with '[Workflow harness — computed task]'
// (a '[Workflow harness — user request]' relay before it is the same for every agent of a workflow, so it says nothing
// about the pass); without one the leading user entries are joined; without a transcript the prompt is unknown.
//
// Pairing. Within one workflow run, kind and round, every shadow pairs with the real pass. A pair counts only when both
// prompts are identical (same diff, same instructions), else it is skipped as differentPrompt; a pair whose prompt
// can't be read is kept as 'unchecked'.
//
// Matching. Findings are matched one-to-one, greedily by best score. Both must name a file with the same basename. When
// both have a line, they match if the lines are at most 5 apart (score 1 - |delta|/10); when either lacks one, they
// match if the Jaccard similarity of their claims' lowercase word tokens (3+ characters) is at least 0.3. Validator
// verdicts join to findings by file basename plus the whitespace-collapsed claim text of the finding each validator
// was given (recorded beside it by the Copilot extension; read from the validator's prompt in a Claude Code journal).
//
// Catch rate. For one side of a pair: raised = its findings, matched = those the partner also found, missed = the
// partner's findings it did not find, union = raised + missed, catch = raised / union, summed over pairs.
// The validated view counts only findings judged valid (their own verdict, else a matched partner's); findings with no
// verdict on either side are left out and counted as unverified. Rows under 5 pairs are flagged thin.
//
// Agreement. When model/effort equals vs, both sides of each pair land in one row, so raised = rA + rB and matched
// counts each match once per side (2m). Catch there is 50% (no shared finding) to 100% (the same set) by construction,
// so those rows report agreement = matched / raised = 2m / (rA + rB) instead (a Dice coefficient, null when nothing
// was raised), with catch null.
//
// Hand-run passes. A plain subagent's description is read after an optional leading AGENTS.md role prefix ('coder: ',
// 'reviewer: ', ...): 'reviewer:' makes it a review pass and any other role prefix makes it not one. Otherwise it is a
// review pass when the description's first token is a review label (as above) or the description names a review or
// re-review; the prompt is never read for this. Its prompt is the text of its first user entry (later leading entries
// are harness reminders that differ per agent). Its report is its last non-empty assistant text, or a later
// SubagentHandback message; without one it failed. Findings are read from the prose report by section: a severity
// heading ('### Minor', '**Nit**', 'Minor:') sets the severity of the list items under it, unless it says none
// ('**Blocker:** none.'), and any other heading resets it; a numbered item or a severity-led title absorbs its
// sub-bullets and continuation lines (a paragraph after a blank line stands alone); a unit is a finding when it has a
// non-negated severity (its own, else its section's) and a file token on any of its lines, and a plain paragraph line
// only when it carries both itself. Negated phrases ('no blockers or serious') never count. Passes pair within one
// (session, parent agent) by identical prompt: every shadow (labelled @shadow, or a description saying shadow) against
// every non-shadow at a different model/effort; a prompt group without both is skipped as noShadow. A pass's issue is
// the first full bd id in its prompt, else in its description; else a shorthand in its description ('h7oc.2', '.2',
// 'issue 2') that matches exactly one id its parent agent named; else the last bd id in the subject of the first commit
// its prompt names (at most 5 tried). Crate and repository names (bd-core, bd-cli, bd-server, bd-sync) are not ids. A
// pair's issue is the real pass's, else the shadow's, and its band falls back to the issue's child change run (role
// 'run') when the issue has no complexity of its own. Descriptions, subjects and prompts are never printed.
// Hand-run passes have no validators. Their verdicts come from the Finding bugs (issue_type bug, title starting
// 'Finding') under the review step of the pair's change run: the issue itself when it is a run (a step counts as its
// run), else the child run its band came from. A bug closed with a fix (fix, address, resolve, or a commit sha) is
// valid; one closed as not a defect, dropped, rejected, a duplicate, won't fix, invalid or a false positive is invalid
// (checked first); an open bug or an unclear close reason gives none. Each pass's blocker and serious findings are
// matched one-to-one to its run's bugs, greedily by tier then score: the same basename with lines at most 10 apart,
// else the same basename with a line missing, else, for a finding or bug naming no file, claims (the bug's title and
// description) at least 0.3 similar. A bug's line is its title's, else the first same-basename mention with a line in
// its title or description. Only blocker and serious findings are filed as bugs, so minor and nit hand-run findings
// stay unverified (though one can take a matched partner's verdict). Where both passes of a pair have a verdict for the
// same finding key, the real pass's wins. bd is listed once per run.
//
// Sources. shadow: a real pass against its shadowReview shadow in the Copilot extension. claude-shadow: the same in the
// Claude Code workflow. hand-shadow: a hand-run real pass against its hand-run shadow (validated from its change run's
// bd Finding bugs, findings from prose, so lossy). The header counts pairs and unknown bands per source, and the
// hand-run findings that got a verdict from bd.
//
// Bands. A pair's band is the confirmed, else judged, else estimated complexity of the run reviewed, and its rubric is
// the integer rubric version on that same metadata object (unknown when missing or not an integer). Rows are keyed by
// rubric version and band, because bands scored under different rubric versions (.bd/rubric.md's Version) are not
// directly comparable.
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bdRunner, claudeRequestsOf, readJson, readJsonl, sessionEvents, subagentsOf } from './trace-run.mjs'

// ---------- labels and models ----------
const EFFORTS = new Set(['low', 'medium', 'high', 'xhigh', 'max'])
const LABEL = /^review:([a-z0-9-]+):r(\d+)(?:@(.+))?$/

/** A review pass's label parsed, or null for any other agent. */
export function parseLabel(label) {
  const m = LABEL.exec(label ?? '')
  if (!m) return null
  const [, kind, round, suffix] = m
  const base = { kind, round: Number(round) }
  if (suffix?.startsWith('shadow:')) {
    const spec = suffix.slice('shadow:'.length)
    const at = spec.lastIndexOf('-')
    const model = spec.slice(0, at)
    const effort = spec.slice(at + 1)
    if (at > 0 && EFFORTS.has(effort)) return { ...base, type: 'shadow', shadow: { model, effort } }
    return null
  }
  return suffix ? null : { ...base, type: 'real' }
}

const CLAUDE_ID = /^(?:[a-z]+\.)*claude-(haiku|sonnet|opus|fable)-(\d+)(?:[-.](\d{1,2}))?(?:-\d{8})?(?:-v\d[\w:]*)?$/

/**
 * A model id in one naming for both harnesses: a Claude id as claude-<class>-<major>[.<minor>] (claude-opus-5-5,
 * claude-opus-5-5-20261001 and claude-opus-5.5[1m] are all claude-opus-5.5), an alias (opus) or any other id as it
 * is, lowercased; 'unknown' when missing.
 */
export function canonicalModel(id) {
  if (typeof id !== 'string' || !id.trim() || id === 'unknown') return 'unknown'
  const s = id.trim().toLowerCase().replace(/\[[^\]]*\]$/, '')
  const m = CLAUDE_ID.exec(s)
  if (!m) return s
  const [, cls, major, minor] = m
  return `claude-${cls}-${major}${minor != null ? `.${minor}` : ''}`
}

const mode = (xs) => {
  const counts = new Map()
  for (const x of xs) counts.set(x, (counts.get(x) ?? 0) + 1)
  let best = null
  for (const [x, c] of counts) if (best == null || c > counts.get(best)) best = x
  return best
}

// ---------- prompts (Claude Code) ----------
export const COMPUTED_TASK = '[Workflow harness — computed task]'

/** The text of a transcript entry: its string content, or its text blocks joined. */
export function textOf(entry) {
  const c = entry?.message?.content
  if (typeof c === 'string') return c
  return Array.isArray(c) ? c.filter((b) => b?.type === 'text' && typeof b.text === 'string').map((b) => b.text).join('\n') : ''
}

/** A workflow agent's prompt from its transcript entries: the computed task, else the leading user entries, else null. */
export function promptOf(entries) {
  if (!entries?.length) return null
  const lead = []
  for (const e of entries) {
    if (e.type === 'assistant') break
    if (e.type === 'user') lead.push(textOf(e))
  }
  const task = lead.find((t) => t.startsWith(COMPUTED_TASK))
  if (task != null) return task
  if (lead.length) return lead.join('\n\n')
  const first = entries.find((e) => e.type === 'user')
  return first ? textOf(first) : null
}

/**
 * Model, effort and prompt of a Claude Code agent from its meta (or null) and transcript entries (or null). The model
 * is the first versioned id of meta's and the transcript requests' most common one, else whichever is known
 * (canonicalModel); effort is meta's when it is a valid effort, else the requests' most common known one.
 */
export function agentFacts(meta, entries) {
  const requests = entries?.length ? claudeRequestsOf(entries) : []
  const models = [meta?.model, mode(requests.map((r) => r.model))].map(canonicalModel).filter((m) => m !== 'unknown')
  return {
    model: models.find((m) => /\d/.test(m)) ?? models[0] ?? 'unknown',
    effort: EFFORTS.has(meta?.effort) ? meta.effort : (mode(requests.map((r) => r.effort).filter((e) => EFFORTS.has(e))) ?? 'unknown'),
    prompt: promptOf(entries),
  }
}

// ---------- passes ----------
const known = (x) => (x && x !== 'unknown' ? x : null)

/**
 * The review passes of one Copilot journal ({ run, agents: [{ label, model, effort, prompt, result }] }): label fields,
 * model, effort, prompt hash and findings, or failed when the agent left no readable findings.
 */
export function passesOf(journal) {
  return journal.agents.flatMap((a) => {
    const label = parseLabel(a.label)
    if (!label) return []
    const findings = Array.isArray(a.result?.findings) ? a.result.findings : null
    return [
      {
        journal: journal.run,
        label: a.label,
        ...label,
        // A shadow's label records the model and effort it was started with, for when the session log is not here.
        model: canonicalModel(known(a.model) ?? label.shadow?.model),
        effort: known(a.effort) ?? label.shadow?.effort ?? 'unknown',
        prompt: a.prompt ?? null,
        findings,
        failed: findings == null,
      },
    ]
  })
}

const parsed = (result) => {
  if (typeof result !== 'string') return result ?? null
  try {
    return JSON.parse(result)
  } catch {
    return null
  }
}

/** Each agent's last 'started' entry matching the label test, with its result (parsed), deduped by agentId. */
function agentsOf(entries, test) {
  const started = new Map()
  for (const e of entries) if (e.type === 'started' && test(e.label)) started.set(e.agentId, e)
  const results = new Map()
  for (const e of entries) if (e.type === 'result') results.set(e.agentId ?? e.key, e)
  return [...started.values()].map((s) => {
    const r = results.get(s.agentId) ?? [...results.values()].find((x) => x.key === s.key)
    return { started: s, result: r ? parsed(r.result) : null }
  })
}

/**
 * The review passes of one Claude Code journal ({ wf, entries, factsOf }), in passesOf's shape. factsOf(agentId)
 * gives agentFacts for the agent.
 */
export function claudePassesOf(journal) {
  const factsOf = journal.factsOf ?? (() => null)
  return agentsOf(journal.entries, (l) => parseLabel(l) != null).map(({ started, result }) => {
    const label = parseLabel(started.label)
    const facts = factsOf(started.agentId) ?? { model: 'unknown', effort: 'unknown', prompt: null }
    // A shadow's label records the model and effort it was started with; the transcript, when readable, wins.
    const model = facts.model !== 'unknown' ? facts.model : canonicalModel(label.shadow?.model)
    const effort = facts.effort !== 'unknown' ? facts.effort : (label.shadow?.effort ?? 'unknown')
    const findings = Array.isArray(result?.findings) ? result.findings : null
    return { journal: journal.wf, agentId: started.agentId, label: started.label, ...label, model, effort, prompt: facts.prompt, findings, failed: findings == null }
  })
}

// ---------- verdicts ----------
const basename = (file) => String(file ?? '').split(/[\\/]/).pop()
const collapse = (s) => String(s ?? '').replace(/\s+/g, ' ').trim()
const keyOf = (file, claim) => `${basename(file)}\0${collapse(claim)}`

/** Verdicts of a Copilot journal's validators, keyed by file basename and collapsed claim text. */
export function validatorsOf(journal) {
  const verdicts = new Map()
  for (const a of journal.agents) {
    if (!a.label?.startsWith('validate:') || typeof a.result?.valid !== 'boolean' || !a.finding) continue
    verdicts.set(keyOf(a.finding.file, a.finding.claim), { valid: a.result.valid, blocking: Boolean(a.result.blocking) })
  }
  return verdicts
}

/** The finding a Claude Code validator was given, from its prompt (fmtFinding's shape): { file, line, claim }, or null. */
export function findingIn(prompt) {
  if (!prompt) return null
  // The finding comes before the ledger, whose settled findings could also carry claims.
  const from = /\n\s*Finding:\n/.exec(prompt)?.index ?? 0
  const m = /\n([^\n]*)\n\s*Claim: ([\s\S]*?)\n\s*Evidence:/.exec(prompt.slice(from))
  if (!m) return null
  const head = m[1]
  const at = head.lastIndexOf(' — ')
  if (at < 0) return null
  const where = /^(.*?)(?::(\d+))?\s*$/.exec(head.slice(at + 3))
  return { file: where[1], line: where[2] ? Number(where[2]) : null, claim: m[2] }
}

/** Verdicts of a Claude Code journal's validators, keyed by file basename and collapsed claim text. */
export function claudeValidatorsOf(journal) {
  const factsOf = journal.factsOf ?? (() => null)
  const verdicts = new Map()
  for (const { started, result } of agentsOf(journal.entries, (l) => typeof l === 'string' && l.startsWith('validate:'))) {
    if (typeof result?.valid !== 'boolean') continue
    const finding = findingIn(factsOf(started.agentId)?.prompt)
    if (finding) verdicts.set(keyOf(finding.file, finding.claim), { valid: result.valid, blocking: Boolean(result.blocking) })
  }
  return verdicts
}

/** The verdict on a finding, or null when no validator judged it. */
export const verdictOf = (finding, verdicts) => verdicts.get(keyOf(finding.file, finding.claim)) ?? null

// A close reason naming a fix (or a commit sha: 7-40 hex characters with at least one digit), and one saying the
// finding was not a defect. NOT_DEFECT is checked first: 'Duplicate of x; fixed in abc1234' is not a fix of its own.
const FIX = /\b(?:fix|address|resolv)|(?<![\w-])(?=[0-9a-f]*\d)[0-9a-f]{7,40}(?![\w-])/i
const NOT_DEFECT = /not a defect|dropp|reject|duplicate|won.?t fix|invalid|false positive/i

/**
 * The verdict a bd Finding bug gives the finding it was filed for: true when it was closed with a fix, false when it
 * was closed as not a defect (dropped, rejected, a duplicate, won't fix, invalid, a false positive), null when it is
 * still open or its close reason says neither.
 */
export function bugVerdict(issue) {
  if (issue?.status !== 'closed') return null
  const reason = String(issue.close_reason ?? '')
  if (NOT_DEFECT.test(reason)) return false
  if (FIX.test(reason)) return true
  return null
}

/**
 * The Finding bugs filed under a change run's review step, from one `bd list --parent <run>.review --all` (closed
 * bugs included) per cache: [{ file, line, claim, valid }], keeping only children under `<run>.review.` whose
 * issue_type is bug and whose title starts with 'Finding' ('Finding: ...' or the workflow's 'Finding F1: ...'). file
 * comes from the title, else the description; when the title's file has no line, its line comes from the first match
 * with the same basename and a line, title first, then description; claim is the title without its 'Finding ...:'
 * prefix plus the description; valid is bugVerdict's. A run whose review step is not a plain issue id never reaches bd;
 * a bd failure or a non-array result gives [] (cached, not retried).
 */
export function verdictsFromBugs(run, bd, cache = new Map()) {
  if (typeof run !== 'string' || !ISSUE_ID.test(run)) return []
  const step = `${run}.review`
  const key = `\0bugs:${run}`
  if (!cache.has(key)) {
    let bugs = []
    try {
      const r = bd(['list', '--parent', step, '--all'])
      bugs = Array.isArray(r) ? r : []
    } catch {
      bugs = []
    }
    cache.set(
      key,
      bugs
        .filter((c) => typeof c?.id === 'string' && c.id.startsWith(`${step}.`) && c.issue_type === 'bug' && /^Finding\b/.test(c.title ?? ''))
        .map((c) => {
          const title = String(c.title).replace(/^Finding\b[^:\n]{0,20}:\s*/, '')
          const description = typeof c.description === 'string' ? c.description : ''
          // the title's file, with a line from the first same-basename match that has one, else the description's first
          const inTitle = FILE.exec(title)
          const lined = inTitle && [...title.matchAll(FILES), ...description.matchAll(FILES)].find((m) => m[2] && basename(m[1]) === basename(inTitle[1]))
          const at = lined || inTitle || FILE.exec(description)
          return { file: at?.[1] ?? null, line: at?.[2] ? Number(at[2]) : null, claim: `${title} ${description}`, valid: bugVerdict(c) }
        }),
    )
  }
  return cache.get(key)
}

// ---------- pairing ----------
/**
 * Pairs of passes over the same diff and prompt: { pairs: [{ source: 'shadow', a, b, prompt }], skipped }. a is the
 * real pass; prompt is 'same', or 'unchecked' when either prompt can't be read.
 */
export function pairPasses(passes) {
  const groups = new Map()
  for (const p of passes) {
    const key = `${p.journal}:${p.kind}:${p.round}`
    groups.set(key, [...(groups.get(key) ?? []), p])
  }
  const pairs = []
  const skipped = { differentPrompt: 0, failed: 0 }
  for (const group of groups.values())
    for (const b of group.filter((p) => p.type === 'shadow'))
      for (const a of group.filter((p) => p.type === 'real')) {
        if (a.failed || b.failed) skipped.failed++
        else if (a.prompt == null || b.prompt == null) pairs.push({ source: 'shadow', a, b, prompt: 'unchecked' })
        else if (a.prompt === b.prompt) pairs.push({ source: 'shadow', a, b, prompt: 'same' })
        else skipped.differentPrompt++
      }
  return { pairs, skipped }
}

// ---------- matching ----------
const lineOf = (f) => {
  const n = Number(f?.line)
  return Number.isFinite(n) && n > 0 ? n : null
}
const tokensOf = (claim) => new Set((String(claim ?? '').toLowerCase().match(/[a-z0-9]+/g) ?? []).filter((t) => t.length >= 3))
const jaccard = (x, y) => {
  const union = new Set([...x, ...y]).size
  return union ? [...x].filter((t) => y.has(t)).length / union : 0
}

/**
 * Greedy one-to-one assignment of scored candidates { i, j, score, tier? } between nA a-items and nB b-items, taking
 * the highest tier (default 0), then the highest score, then the lowest i and j first: { matches: [[i, j]], aOnly: [i],
 * bOnly: [j] }.
 */
function oneToOne(candidates, nA, nB) {
  const sorted = candidates.toSorted((x, y) => (y.tier ?? 0) - (x.tier ?? 0) || y.score - x.score || x.i - y.i || x.j - y.j)
  const usedA = new Set()
  const usedB = new Set()
  const matches = []
  for (const { i, j } of sorted)
    if (!usedA.has(i) && !usedB.has(j)) {
      usedA.add(i)
      usedB.add(j)
      matches.push([i, j])
    }
  return {
    matches,
    aOnly: Array.from({ length: nA }, (_, i) => i).filter((i) => !usedA.has(i)),
    bOnly: Array.from({ length: nB }, (_, j) => j).filter((j) => !usedB.has(j)),
  }
}

/** One-to-one matches between two passes' findings: { matches: [[i, j]], aOnly: [i], bOnly: [j] }. */
export function matchFindings(as, bs) {
  const candidates = []
  for (const [i, a] of as.entries())
    for (const [j, b] of bs.entries()) {
      if (basename(a.file) !== basename(b.file)) continue
      const la = lineOf(a)
      const lb = lineOf(b)
      if (la != null && lb != null) {
        const delta = Math.abs(la - lb)
        if (delta <= 5) candidates.push({ i, j, score: 1 - delta / 10 })
      } else {
        const score = jaccard(tokensOf(a.claim), tokensOf(b.claim))
        if (score >= 0.3) candidates.push({ i, j, score })
      }
    }
  return oneToOne(candidates, as.length, bs.length)
}

/**
 * Verdicts for a hand-run pass's findings from its change run's Finding bugs (verdictsFromBugs), in validatorsOf's
 * shape: a Map keyed by file basename and collapsed claim to { valid, blocking: false }. Only blocker and serious
 * findings are candidates (only those are filed as bugs). Each finding takes at most one bug and each bug one finding,
 * greedy by tier then score: the same basename with lines at most 10 apart, else the same basename with a line missing
 * (scored by claim similarity), else, when the finding or the bug names no file, claims at least 0.3 similar. When both
 * name a file, a bug naming another file never matches. A finding matched to a bug with no verdict (still open) is used
 * up but gets no entry.
 */
export function matchBugs(findings, bugs) {
  const serious = findings.filter((f) => f?.severity === 'blocker' || f?.severity === 'serious')
  const candidates = []
  for (const [i, f] of serious.entries())
    for (const [j, b] of bugs.entries()) {
      const score = () => jaccard(tokensOf(f.claim), tokensOf(b.claim))
      if (!f.file || !b.file) {
        const s = score()
        if (s >= 0.3) candidates.push({ i, j, tier: 0, score: s })
        continue
      }
      if (basename(f.file) !== basename(b.file)) continue
      const lf = lineOf(f)
      const lb = lineOf(b)
      if (lf != null && lb != null) {
        const delta = Math.abs(lf - lb)
        if (delta <= 10) candidates.push({ i, j, tier: 2, score: 1 - delta / 20 })
      } else candidates.push({ i, j, tier: 1, score: score() })
    }
  const verdicts = new Map()
  for (const [i, j] of oneToOne(candidates, serious.length, bugs.length).matches)
    if (typeof bugs[j].valid === 'boolean') verdicts.set(keyOf(serious[i].file, serious[i].claim), { valid: bugs[j].valid, blocking: false })
  return verdicts
}

// ---------- aggregate ----------
/**
 * The two observations of a pair, one per side, each counted against the other side's model and effort, with the band
 * of the run reviewed and the rubric version it was scored under (null, unknown, when not given).
 */
export function observe(pair, band, verdicts, rubric = null) {
  const { a, b } = pair
  const { matches, aOnly, bOnly } = matchFindings(a.findings, b.findings)
  const partnerOfA = new Map(matches.map(([i, j]) => [i, j]))
  const partnerOfB = new Map(matches.map(([i, j]) => [j, i]))
  // true / false, or null when neither the finding nor its matched partner has a verdict.
  const validity = (own, partner) => {
    const v = verdictOf(own, verdicts) ?? (partner ? verdictOf(partner, verdicts) : null)
    return v ? v.valid : null
  }
  const side = (self, other, partnerOf, missedIdx) => {
    const own = self.findings.map((f, i) => validity(f, partnerOf.has(i) ? other.findings[partnerOf.get(i)] : null))
    const missed = missedIdx.map((j) => validity(other.findings[j], null))
    return {
      model: self.model,
      effort: self.effort,
      vs: `${other.model}/${other.effort}`,
      rubric,
      band,
      all: { raised: self.findings.length, matched: matches.length, missed: missedIdx.length },
      validated: {
        raised: own.filter((v) => v === true).length,
        matched: [...partnerOf.keys()].filter((i) => own[i] === true).length,
        missed: missed.filter((v) => v === true).length,
        unverified: own.filter((v) => v === null).length,
      },
    }
  }
  // One identity per call, shared by both sides, so aggregate() counts a pair once when both land in one row.
  // Non-enumerable: it is bookkeeping, not part of the observation's data.
  const id = Symbol('pair')
  return [side(a, b, partnerOfA, bOnly), side(b, a, partnerOfB, aOnly)].map((o) => Object.defineProperty(o, 'pair', { value: id }))
}

// Rubric versions ascending, null (unknown) last.
const rubricOrder = (x, y) => (x == null ? (y == null ? 0 : 1) : y == null ? -1 : x - y)

const bandOrder = (x, y) => {
  const nx = typeof x === 'number' ? x : Number.POSITIVE_INFINITY
  const ny = typeof y === 'number' ? y : Number.POSITIVE_INFINITY
  return nx - ny || String(x).localeCompare(String(y))
}

/**
 * Observations summed into rows by rubric version, band, model/effort and partner model/effort, for both views.
 * A row where model equals vs has sameLevel true, catch null and agreement = matched / raised (null if raised is 0).
 */
export function aggregate(observations) {
  const view = (name) => {
    const rows = new Map()
    const pairsOf = new Map() // key -> Set of pair identities, kept out of the rows
    for (const o of observations) {
      const modelEffort = `${o.model}/${o.effort}`
      const key = `${o.rubric ?? 'unknown'}\0${o.band}\0${modelEffort}\0${o.vs}`
      const row = rows.get(key) ?? {
        rubric: o.rubric ?? null,
        band: o.band,
        model: modelEffort,
        vs: o.vs,
        pairs: 0,
        raised: 0,
        matched: 0,
        missed: 0,
        ...(name === 'validated' ? { unverified: 0 } : {}),
      }
      const ids = pairsOf.get(key) ?? new Set()
      ids.add(o.pair ?? Symbol('pair'))
      pairsOf.set(key, ids)
      row.pairs = ids.size
      for (const f of ['raised', 'matched', 'missed', ...(name === 'validated' ? ['unverified'] : [])]) row[f] += o[name][f]
      rows.set(key, row)
    }
    return [...rows.values()]
      .map((r) => {
        const union = r.raised + r.missed
        const sameLevel = r.model === r.vs
        return Object.assign(r, {
          union,
          catch: sameLevel || !union ? null : r.raised / union,
          sameLevel,
          ...(sameLevel ? { agreement: r.raised ? r.matched / r.raised : null } : {}),
          thin: r.pairs < 5,
        })
      })
      .toSorted((x, y) => rubricOrder(x.rubric, y.rubric) || bandOrder(x.band, y.band) || x.model.localeCompare(y.model) || x.vs.localeCompare(y.vs))
  }
  return { all: view('all'), validated: view('validated') }
}

// ---------- render ----------
const pct = (x) => (x == null ? '–' : `${Math.round(x * 100)}%`)
const table = (head, rows) => [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.join(' | ')} |`)].join('\n')
const rowsTable = (rows) =>
  rows.length
    ? table(
        ['rubric', 'band', 'model/effort', 'vs', 'pairs', 'raised', 'matched', 'missed', 'catch', 'agree', 'thin'],
        rows.map((r) => [r.rubric == null ? 'unknown' : `v${r.rubric}`, r.band, r.model, r.vs, r.pairs, r.raised, r.matched, r.missed, pct(r.catch), pct(r.agreement), r.thin ? 'thin' : '']),
      )
    : 'No pairs.'

const unknownBand = (p) => p.band === 'unknown'

// Pair sources in header order, with their labels.
const SOURCES = [
  ['shadow', 'Copilot real vs shadow'],
  ['claude-shadow', 'Claude Code real vs shadow'],
  ['hand-shadow', 'hand-run real vs shadow'],
]

/**
 * The report as markdown. data: { journals, claudeJournals, hand, passes, failed, handPasses, handFailed, handVerdicts,
 * currentRubric, pairs: [{ source, prompt, band }], skipped: { differentPrompt, failed, noShadow }, rows: { all,
 * validated } }; missing counts read as 0. Rows carry a rubric version (printed v<N>, or unknown when null). Prints only
 * counts, labels, models, efforts, rubric versions and bands: never claims, paths, prompts, descriptions or issue ids.
 */
export function render(data) {
  const pairs = data.pairs ?? []
  const skipped = data.skipped ?? {}
  const unverified = data.rows.validated.reduce((n, r) => n + r.unverified, 0)
  const bySource = SOURCES.map(([s, label]) => {
    const of = pairs.filter((p) => p.source === s)
    return `${of.length} ${label} (${of.filter(unknownBand).length})`
  })
  return [
    `# Reviewer catch rate`,
    ``,
    `${data.journals ?? 0} Copilot workflow runs and ${data.claudeJournals ?? 0} Claude Code workflow journals, ${data.passes ?? 0} review passes (${data.failed ?? 0} failed); ` +
      `${data.hand ?? 0} hand-run groups, ${data.handPasses ?? 0} hand-run review passes (${data.handFailed ?? 0} failed).`,
    `${pairs.length} pairs by source (band unknown): ${bySource.join(', ')}.`,
    `Skipped: ${skipped.differentPrompt ?? 0} with different prompts, ${skipped.failed ?? 0} with a failed side, ` +
      `${skipped.noShadow ?? 0} hand-run prompts without both a real and a shadow pass. ` +
      `${pairs.filter((p) => p.prompt === 'unchecked').length} with the prompt unchecked, ${pairs.filter(unknownBand).length} with the band unknown.`,
    `${data.handVerdicts ?? 0} hand-run findings got a verdict from bd (their change run's Finding bugs).`,
    `Current rubric (.bd/rubric.md): ${data.currentRubric == null ? 'unknown' : `v${data.currentRubric}`}.`,
    ``,
    `## All findings`,
    ``,
    rowsTable(data.rows.all),
    ``,
    `## Validated findings only`,
    ``,
    rowsTable(data.rows.validated),
    ``,
    `${unverified} findings had no verdict on either side and are left out of this view.`,
    ``,
    `Each row is one side of its pairs: its model/effort against its partner's (vs), in the complexity band of the run reviewed; rubric is the rubric version that band was scored under, and bands of different versions are not compared. ` +
      `Models are named by id in one form for both harnesses (Claude Code's claude-opus-5-5 is claude-opus-5.5), so Copilot and Claude Code passes at the same model and effort share a row; a model known only by an alias (opus) is kept apart. ` +
      `Findings match one-to-one on the same file basename, with lines at most 5 apart, or similar claims when a line is missing. ` +
      `missed = the partner's findings this side did not raise; catch = raised / union, with union = raised + missed, summed over pairs. ` +
      `Where model/effort equals vs, both sides of each pair sum into one row, so catch would be 50% to 100% by construction; those rows show agree = matched / raised instead (matched counts each match once per side), and catch –. ` +
      `Thin rows have under 5 pairs. ` +
      `hand-shadow pairs come from review subagents run outside workflows. They are paired by identical prompt, their issue comes from the prompt, the description, a shorthand the parent named, or a reviewed commit's subject, and their findings are read from prose reports (lossy). They have no validators: a blocker or serious hand-run finding takes the verdict of the bd Finding bug it matches under its change run's review step (closed with a fix: valid; closed as not a defect, dropped, rejected, a duplicate, won't fix or invalid: invalid; open: none), one-to-one on the same file basename with lines at most 10 apart, or similar claims when either names no file. Only blocker and serious findings are filed as bugs, so minor and nit hand-run findings stay unverified.`,
  ].join('\n')
}

// ---------- hand-run passes ----------
export const ROLE_PREFIXES = ['coder', 'reviewer', 'mechanical', 'research', 'planner', 'summary']
// The AGENTS.md role prefixes: the one list, which calibrate.mjs imports for roleOf and its methodology note. The words
// are plain lowercase letters, so they go into the regex unescaped. No '<agentType>: ' skip group here, since
// meta.description is the bare description.
const ROLE_PREFIX = new RegExp(`^\\s*(${ROLE_PREFIXES.join('|')}):\\s*`, 'i')

/**
 * A plain subagent's review facts from its meta, or null when it is not a review pass: { label, kind, round, shadow,
 * shadowSpec }. The description is read after an optional leading AGENTS.md role prefix: 'reviewer:' makes a pass and
 * any other role prefix ('coder:', 'planner:', ...) makes it not one. Otherwise a review:<kind>:r<N>[@shadow:<model>-
 * <effort>] label as the first token or a description naming a review or re-review make a pass. Reads the description,
 * never the prompt.
 */
export function handReview(meta) {
  const desc = typeof meta?.description === 'string' ? meta.description : ''
  const pm = ROLE_PREFIX.exec(desc)
  const role = pm?.[1].toLowerCase()
  if (role && role !== 'reviewer') return null
  const rest = pm ? desc.slice(pm[0].length) : desc
  const token = rest.trim().split(/\s+/)[0]
  const l = parseLabel(token)
  const shadow = /\bshadow\b/i.test(rest)
  if (l) return { label: token, kind: l.kind, round: l.round, shadow: l.type === 'shadow' || shadow, shadowSpec: l.shadow ?? null }
  if (role !== 'reviewer' && !/\b(?:re-?review|review)\b/i.test(rest)) return null
  const r = /\br(\d+)\b/i.exec(rest)
  return { label: null, kind: 'code', round: r ? Number(r[1]) : /\bre-?review\b/i.test(rest) ? null : 0, shadow, shadowSpec: null }
}

/** The tool a subagent can hand its report back with. */
export const SUBAGENT_HANDBACK = 'SubagentHandback'

/**
 * A subagent's report from its transcript entries: the last non-empty assistant text block, or a SubagentHandback
 * message when that comes later; null when there is neither.
 */
export function reportOf(entries) {
  let found = null
  for (const e of entries ?? []) {
    if (e?.type !== 'assistant') continue
    const c = e.message?.content
    if (typeof c === 'string') {
      if (c.trim()) found = c
      continue
    }
    if (!Array.isArray(c)) continue
    for (const b of c) {
      if (b?.type === 'text' && typeof b.text === 'string' && b.text.trim()) found = b.text
      else if (b?.type === 'tool_use' && b.name === SUBAGENT_HANDBACK && typeof b.input?.message === 'string' && b.input.message.trim()) found = b.input.message
    }
  }
  return found
}

// NEG is global: use it only with replace, never .test or .exec, whose results would depend on lastIndex.
const NEG = /\b(?:no|zero|without|not\s+any)\s+(?:(?:new|open|remaining|other|further)\s+)?(?:blockers?|serious|minor|nits?)(?:\s*(?:,|\/|\bor\b|\band\b|\bnor\b)\s*(?:no\s+)?(?:blockers?|serious|minor|nits?))*/gi
const unneg = (s) => s.replace(NEG, ' ')
const negated = (s) => unneg(s) !== s
const SEV = /\b(blocker|serious|minor|nit)s?\b/i
const SEVS = /\b(blocker|serious|minor|nit)s?\b/gi
const FILE = /(?<![\w.@+-])([\w.@+-]+\.(?:rs|svelte|ts|js|mjs|cjs|css|md|toml|json|html|yml|yaml|sh))(?::(\d+))?(?![\w])/
// FILE's matches, all of them (matchAll copies the regex, so no lastIndex state is shared)
const FILES = new RegExp(FILE.source, 'g')
const ITEM = /^(?:[-*+]|\d+[.)])\s+/
const NUMBERED = /^(?:\*\*|__)?\d+[.)]\s+/
const LEAD = /^(blocker|serious|minor|nit)s?\b/i
const SEV_LABEL = /^(?:\*\*|__)?(?:blocker|serious|minor|nit)s?\b[^:\n]{0,40}:/i
const BOLD_LABEL = /^(\*\*|__)[^*_\n]{1,40}:(\*\*|__)/
const SHORT_LINE = /^[A-Za-z][^.:!?`]{0,60}:?\s*$/
const SEV_WORD = /^(?:blocker|serious|minor|nit)s?$/i
const LIST_JOIN = /^(?:and|or)$/i
const FILLER = /^(?:findings?|issues?|items?|optional|informational|none|only|no|found)$/i
const MAX_LINE = 4000

const plain = (l) =>
  l
    .trim()
    .replace(/^#+/, '')
    .replace(/\*\*|__|`/g, '')
    .trim()
    .replace(ITEM, '')
    .replace(/\s+/g, ' ')
    .trim()

const isHeading = (l) => {
  if (/^#{1,6}\s+\S/.test(l) || BOLD_LABEL.test(l) || SHORT_LINE.test(l) || SEV_LABEL.test(l)) return true
  const t = l.trim()
  if (t.length <= 4) return false
  for (const m of ['**', '__']) if (t.startsWith(m) && (t.endsWith(m) || t.endsWith(`${m}:`) || t.endsWith(`:${m}`))) return true
  return false
}

// A heading's words after its leading severity words, parentheticals stripped.
const restOf = (p) => {
  const words = p
    .replace(/\([^()]{0,200}\)/g, ' ')
    .split(/[^A-Za-z]+/)
    .filter(Boolean)
  let i = 0
  while (i < words.length && (SEV_WORD.test(words[i]) || (i > 0 && LIST_JOIN.test(words[i])))) i++
  return words.slice(i)
}

// A heading that says only which severity it is ('Minor, optional (low):', '**Blocker:** none.'), not a finding.
const pure = (p) => restOf(p).every((w) => FILLER.test(w))

// A severity heading that says there are none ('**Blocker:** none.', 'Serious: none'): it resets the section.
const NONE = /^(?:none|no)$/i
const saysNone = (p) => {
  const rest = restOf(p)
  return rest.some((w) => NONE.test(w)) && rest.every((w) => FILLER.test(w))
}

/**
 * Findings read from a prose review report: [{ file, line, severity, claim }]. A severity heading sets the severity of
 * the list items under it, unless it says none ('**Blocker:** none.'), and any other heading resets it. A numbered
 * item or a severity-led title absorbs its sub-bullets and continuation lines, but not a paragraph after a blank line;
 * a top-level bullet starts its own unit; a plain paragraph line stands alone and needs its own severity. A unit is a
 * finding when it has a non-negated severity (its first line's, else its section's) and a file token on any of its
 * lines; a unit whose first line only negates severities is not. The claim is the unit's first line without markdown.
 */
export function findingsIn(prose) {
  if (typeof prose !== 'string') return []
  const out = []
  let cur = null
  let unit = null
  let gap = false
  const flush = () => {
    const u = unit
    unit = null
    if (!u) return
    const first = u.lines[0]
    const own = SEV.exec(unneg(first))
    if (!own && negated(first)) return
    const severity = own ? own[1].toLowerCase() : u.sev
    if (!severity) return
    for (const l of u.lines) {
      const m = FILE.exec(l)
      if (m) {
        out.push({ file: m[1], line: m[2] ? Number(m[2]) : null, severity, claim: plain(first) })
        return
      }
    }
  }
  for (const raw of prose.split('\n')) {
    const l = raw.slice(0, MAX_LINE).trimEnd()
    if (!l.trim()) {
      gap = true
      continue
    }
    const after = gap
    gap = false
    const top = !/^\s/.test(l)
    if (top && NUMBERED.test(l)) {
      flush()
      unit = { lines: [l], sev: cur, titled: true }
    } else if (top && !ITEM.test(l) && isHeading(l)) {
      flush()
      const p = unneg(plain(l))
      const sevs = new Set([...p.matchAll(SEVS)].map((m) => m[1].toLowerCase()))
      cur = sevs.size === 1 && !saysNone(p) ? [...sevs][0] : null
      if (LEAD.test(p) && !pure(p)) unit = { lines: [l], sev: cur, titled: true }
    } else if (top && ITEM.test(l)) {
      if (unit?.titled && !SEV.test(unneg(l))) unit.lines.push(l)
      else {
        flush()
        unit = { lines: [l], sev: cur, titled: false }
      }
    } else if (!top && unit) unit.lines.push(l)
    else if (unit?.titled && !after) unit.lines.push(l)
    else {
      flush()
      unit = { lines: [l], sev: null, titled: false }
      flush()
    }
  }
  flush()
  return out
}

// bd issue ids of this workspace: 'bd-' then base36, with optional .segments, standing alone. The crates and the
// repository are named like ids (bd-core, bd-cli, bd-server, bd-sync), so those names never count, nor anything after
// a '/', '.' or '-' (a path, a domain, a longer name).
const ISSUE_PREFIX = 'bd'
const ISSUE_IN_TEXT = new RegExp(`(?<![\\w./-])${ISSUE_PREFIX}-[a-z0-9]+(?:\\.[a-z0-9-]+)*(?![\\w-])`, 'g')
const NOT_ISSUES = new Set(['bd-sync', 'bd-core', 'bd-cli', 'bd-server', 'bd-serve', 'bd-web'])

/** The bd issue ids a text names, in order of first appearance, without crate and repository names. */
export function namedIssues(text) {
  if (typeof text !== 'string') return []
  return [...new Set(text.match(ISSUE_IN_TEXT) ?? [])].filter((id) => !NOT_ISSUES.has(id.split('.')[0]))
}

const SHA = /^[0-9a-f]{7,40}$/
const SHORTHAND = /(?<![\w-])([a-z][a-z0-9]*)?\.(\d+)(?![\w.])|\bissue\s+(\d+)\b/gi
const HEX = /(?<![\w-])([0-9a-f]{7,40})(?![\w-])/g
const MAX_SHAS = 5

/** A hand-run pass's prompt: the text of its first user entry before any assistant entry (the Agent prompt), else null. */
export function handPromptOf(entries) {
  for (const e of entries ?? []) {
    if (e?.type === 'assistant') return null
    if (e?.type === 'user') return textOf(e)
  }
  return null
}

/**
 * The bd issue a hand-run pass reviewed, or null: the first full id in its prompt, else in its description; else a
 * shorthand in its description ('h7oc.2', '.2', 'issue 2') that ends exactly one of the parent agent's ids (a prefixed
 * shorthand must also match the id's prefix: 'h7oc.2' ends 'bd-h7oc.2' but not 'bd-abc.2'); else the last id in the
 * subject (subjectOf) of the first commit its prompt names, of at most 5 tried.
 */
export function handIssue({ prompt, description, parentIds = [], subjectOf = () => null }) {
  const full = namedIssues(prompt)[0] ?? namedIssues(description)[0]
  if (full) return full
  if (typeof description === 'string')
    for (const m of description.matchAll(SHORTHAND)) {
      const p = m[1]?.toLowerCase()
      const n = m[2] ?? m[3]
      const c = parentIds.filter((id) => (p ? id.endsWith(`-${p}.${n}`) || id.endsWith(`.${p}.${n}`) : id.endsWith(`.${n}`)))
      if (c.length === 1) return c[0]
    }
  if (typeof prompt !== 'string') return null
  const shas = [...new Set([...prompt.matchAll(HEX)].map((m) => m[1]))].filter((t) => /\d/.test(t) && /[a-f]/.test(t)).slice(0, MAX_SHAS)
  for (const sha of shas) {
    if (!SHA.test(sha)) continue
    const ids = namedIssues(subjectOf(sha))
    if (ids.length) return ids.at(-1)
  }
  return null
}

/** A cached reader of a commit's subject in the root checkout (read-only `git log -1 --format=%s`), null on any error. */
export function gitSubject(root) {
  const cache = new Map()
  return (sha) => {
    if (typeof sha !== 'string' || !SHA.test(sha)) return null
    if (!cache.has(sha)) {
      let subject = null
      try {
        subject = execFileSync('git', ['-C', root, 'log', '-1', '--format=%s', sha], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).trim()
      } catch {
        subject = null
      }
      cache.set(sha, subject)
    }
    return cache.get(sha)
  }
}

/**
 * Hand-run passes paired by identical prompt, each shadow against each real pass at a different model/effort:
 * { pairs: [{ source: 'hand-shadow', a, b, prompt: 'same' }], skipped: { noShadow, failed } }. A prompt group of two
 * or more without both a real and a shadow pass counts once in noShadow.
 */
export function pairHandPasses(passes) {
  const groups = new Map()
  for (const p of passes) if (p.prompt != null) groups.set(p.prompt, [...(groups.get(p.prompt) ?? []), p])
  const pairs = []
  const skipped = { noShadow: 0, failed: 0 }
  for (const group of groups.values()) {
    if (group.length < 2) continue
    const shadows = group.filter((p) => p.type === 'shadow')
    const reals = group.filter((p) => p.type !== 'shadow')
    if (!shadows.length || !reals.length) {
      skipped.noShadow++
      continue
    }
    for (const s of shadows)
      for (const r of reals) {
        if (`${r.model}/${r.effort}` === `${s.model}/${s.effort}`) continue
        if (r.failed || s.failed) skipped.failed++
        else pairs.push({ source: 'hand-shadow', a: r, b: s, prompt: 'same' })
      }
  }
  return { pairs, skipped }
}

// ---------- journals ----------
const list = (dir) => (existsSync(dir) ? readdirSync(dir) : [])
const RUN_FILE = /^[0-9a-f-]{36}\.jsonl$/

/**
 * Every run the Copilot extension recorded on this machine: { run, workflow, args: { reviewStep, issue }, agents:
 * [{ label, model, effort, prompt, result, finding }] }. An agent's model and effort come from its subagent events
 * (matched by workflow run and label), else what the workflow asked for. A run resumed after a pause recorded its
 * replayed agents again: each label and prompt counts once, the last record standing.
 */
export function readJournals(sessionsDir) {
  return list(sessionsDir).flatMap((session) => {
    const dir = join(sessionsDir, session, 'files', 'workflow-agents')
    const files = list(dir).filter((f) => RUN_FILE.test(f))
    if (!files.length) return []
    const { agents: started } = existsSync(join(sessionsDir, session, 'events.jsonl')) ? subagentsOf(sessionEvents(sessionsDir, session)) : { agents: new Map() }
    const ran = new Map()
    for (const a of started.values()) if (a.workflowRunId) ran.set(`${a.workflowRunId}\0${a.agentDisplayName}`, a)
    return files.map((f) => {
      const run = f.slice(0, -'.jsonl'.length)
      const records = readJsonl(join(dir, f))
      const header = records.find((r) => r.type === 'run')
      const byKey = new Map()
      for (const r of records.filter((r) => r.type === 'agent' && typeof r.label === 'string')) byKey.set(`${r.label}\0${r.prompt_sha256}`, r)
      const agents = [...byKey.values()].map((r) => {
        const actual = ran.get(`${run}\0${r.label}`)
        return {
          label: r.label,
          model: actual?.model ?? r.model ?? 'unknown',
          effort: actual?.effort ?? r.effort ?? 'unknown',
          prompt: r.prompt_sha256 ?? null,
          result: r.result ?? null,
          finding: r.finding ?? null,
        }
      })
      return { run, workflow: header?.workflow ?? null, args: header ? { reviewStep: header.reviewStep, issue: header.issue } : null, agents }
    })
  })
}

/** A checkout path as Claude Code names its projects directory. */
export const encodeProject = (path) => path.replace(/[^a-zA-Z0-9]/g, '-')

/** This project's directories under projectsDir: the main checkout's and its .claude/worktrees/* checkouts'. */
export function projectDirs(projectsDir, root) {
  const checkout = encodeProject(root)
  const worktrees = `${encodeProject(join(root, '.claude/worktrees'))}-`
  return list(projectsDir).filter((d) => d === checkout || d.startsWith(worktrees))
}

const AGENT_ID = /^[0-9a-zA-Z_-]+$/

/**
 * Every Claude Code workflow journal of this project: { harness: 'claude', wf, workflow, args, entries, factsOf }.
 * factsOf(agentId) reads the agent's meta and transcript beside the journal, once, into agentFacts.
 */
export function readClaudeJournals(projectsDir, root) {
  return projectDirs(projectsDir, root).flatMap((project) =>
    list(join(projectsDir, project)).flatMap((session) => {
      const workflows = join(projectsDir, project, session, 'subagents', 'workflows')
      return list(workflows).flatMap((wf) => {
        const dir = join(workflows, wf)
        const file = join(dir, 'journal.jsonl')
        if (!existsSync(file)) return []
        const record = readJson(join(projectsDir, project, session, 'workflows', `${wf}.json`))
        let args = record?.args ?? null
        if (typeof args === 'string')
          try {
            args = JSON.parse(args)
          } catch {
            args = null
          }
        const facts = new Map()
        const factsOf = (id) => {
          if (typeof id !== 'string' || !AGENT_ID.test(id)) return agentFacts(null, null)
          if (!facts.has(id)) {
            const transcript = join(dir, `agent-${id}.jsonl`)
            facts.set(id, agentFacts(readJson(join(dir, `agent-${id}.meta.json`)), existsSync(transcript) ? readJsonl(transcript) : null))
          }
          return facts.get(id)
        }
        return [{ harness: 'claude', wf, workflow: record?.workflowName ?? null, args: args && typeof args === 'object' ? args : null, entries: readJsonl(file), factsOf }]
      })
    }),
  )
}

const HAND_META = /^agent-([0-9a-zA-Z_-]+)\.meta\.json$/

/**
 * Every review pass run as a plain subagent (agent-<id>.meta.json and .jsonl directly under <session>/subagents/, never
 * under workflows/), grouped by session and parent agent: [{ wf, workflow: 'hand', args: null, passes }]. A pass is
 * { journal, agentId, label, kind, round, type ('shadow' or 'real'), model, effort, prompt, findings, failed, issue };
 * its description, the parent's ids and any commit subject are read but never kept.
 */
export function readHandPasses(projectsDir, root, { subjectOf = gitSubject(root) } = {}) {
  const groups = new Map()
  for (const project of projectDirs(projectsDir, root))
    for (const session of list(join(projectsDir, project))) {
      const dir = join(projectsDir, project, session, 'subagents')
      const parents = new Map()
      const parentIds = (parent) => {
        if (!parents.has(parent)) {
          let ids = []
          const transcript = join(dir, `agent-${parent}.jsonl`)
          if (parent !== 'main' && AGENT_ID.test(parent) && existsSync(transcript)) {
            const meta = readJson(join(dir, `agent-${parent}.meta.json`))
            const desc = typeof meta?.description === 'string' ? meta.description : ''
            ids = namedIssues(`${handPromptOf(readJsonl(transcript)) ?? ''}\n${desc}`)
          }
          parents.set(parent, ids)
        }
        return parents.get(parent)
      }
      for (const f of list(dir)) {
        const agentId = HAND_META.exec(f)?.[1]
        if (!agentId || !AGENT_ID.test(agentId)) continue
        const meta = readJson(join(dir, f))
        const rec = handReview(meta)
        if (!rec) continue
        const transcript = join(dir, `agent-${agentId}.jsonl`)
        const entries = existsSync(transcript) ? readJsonl(transcript) : null
        const facts = agentFacts(meta, entries)
        const model = facts.model !== 'unknown' ? facts.model : canonicalModel(rec.shadowSpec?.model)
        const effort = facts.effort !== 'unknown' ? facts.effort : (rec.shadowSpec?.effort ?? 'unknown')
        const prompt = handPromptOf(entries)
        const prose = entries ? reportOf(entries) : null
        const findings = prose == null ? null : findingsIn(prose)
        const parent = typeof meta.parentAgentId === 'string' ? meta.parentAgentId : 'main'
        const desc = typeof meta.description === 'string' ? meta.description : ''
        const issue = handIssue({ prompt, description: desc, parentIds: parentIds(parent), subjectOf })
        const wf = `hand:${session}:${parent}`
        const pass = { journal: wf, agentId, label: rec.label, kind: rec.kind, round: rec.round, type: rec.shadow ? 'shadow' : 'real', model, effort, prompt, findings, failed: findings == null, issue }
        const key = `${project}\0${session}\0${parent}`
        if (!groups.has(key)) groups.set(key, { wf, workflow: 'hand', args: null, passes: [] })
        groups.get(key).passes.push(pass)
      }
    }
  return [...groups.values()]
}

// ---------- bands ----------
const ISSUE_ID = /^[a-z0-9.-]+$/
const ISSUE_IN_PROMPT = /\(bd issue: ([a-z0-9.-]+)/

/** The bd issue a workflow worked on: its run record's reviewStep (as its run) or issue, else one named in a prompt. */
export function runOf(args, prompts) {
  if (typeof args?.reviewStep === 'string') return args.reviewStep.replace(/\.review$/, '')
  if (typeof args?.issue === 'string') return args.issue
  for (const p of prompts ?? []) {
    const m = ISSUE_IN_PROMPT.exec(p ?? '')
    if (m) return m[1]
  }
  return null
}

// A rubric version: an integer, else null.
const versionOf = (x) => (Number.isInteger(x) ? x : null)

// The confirmed, else judged, else estimated complexity in an issue's metadata, with the rubric version of the same
// object, or null.
const bandFrom = (md) => {
  if (md?.score?.complexity != null) return { band: md.score.complexity, source: 'confirmed', rubric: versionOf(md.score.rubric) }
  if (md?.score_judge?.complexity != null) return { band: md.score_judge.complexity, source: 'judged', rubric: versionOf(md.score_judge.rubric) }
  if (md?.complexity_estimate?.score != null) return { band: md.complexity_estimate.score, source: 'estimate', rubric: versionOf(md.complexity_estimate.rubric) }
  return null
}

/**
 * The complexity band of a bd issue (a playbook step counts as its run): { band, source, rubric, run }, with source
 * 'confirmed', 'judged' or 'estimate' and rubric the integer rubric version on the same metadata object (score,
 * score_judge or complexity_estimate; null when missing or not an integer), or band 'unknown', source null and rubric
 * null. An issue that exists but carries no complexity falls back to its child change runs (children whose
 * metadata.playbook.role is 'run', listed with `list --parent <id> --all` because finished runs are closed), in id
 * order, taking the first with a band and that band's rubric version. run is the change run the band came from: the
 * issue itself (after step resolution) when its metadata.playbook.role is 'run', else the child run whose band was
 * taken, else null. bd(args) returns parsed `bd ... --json` output; each id is shown and listed at most once per cache,
 * and an id that isn't a plain issue id never reaches bd.
 */
export function runBandOf(id, bd, cache = new Map()) {
  const show = (x) => {
    if (typeof x !== 'string' || !ISSUE_ID.test(x)) return null
    if (!cache.has(x)) {
      let issue = null
      try {
        const r = bd(['show', x])
        issue = (Array.isArray(r) ? r[0] : r) ?? null
      } catch {
        issue = null
      }
      cache.set(x, issue)
    }
    return cache.get(x)
  }
  let rid = id
  let issue = show(id)
  const playbook = issue?.metadata?.playbook
  if (playbook?.role === 'step') {
    rid = playbook.run
    issue = show(rid)
  }
  if (issue == null) return { band: 'unknown', source: null, rubric: null, run: null }
  const run = issue.metadata?.playbook?.role === 'run' ? rid : null
  const own = bandFrom(issue.metadata)
  if (own) return { ...own, run }
  // rid passed ISSUE_ID in show(), so the list call only ever gets a plain issue id.
  const key = `\0list:${rid}`
  if (!cache.has(key)) {
    let children = []
    try {
      const r = bd(['list', '--parent', rid, '--all'])
      children = Array.isArray(r) ? r : []
    } catch {
      children = []
    }
    cache.set(key, children)
  }
  const children = cache
    .get(key)
    .filter((c) => typeof c?.id === 'string' && c.id.startsWith(`${rid}.`) && (c.metadata == null || c.metadata.playbook?.role === 'run'))
    .toSorted((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0))
  for (const c of children) {
    // A child listed without metadata is shown (show() checks its id) to learn whether it is a run.
    const md = c.metadata ?? show(c.id)?.metadata
    if (md?.playbook?.role !== 'run') continue
    const band = bandFrom(md)
    if (band) return { ...band, run: run ?? c.id }
  }
  return { band: 'unknown', source: null, rubric: null, run }
}

/** runBandOf's { band, source, rubric }, without the run. */
export function bandOf(id, bd, cache = new Map()) {
  const { run: _run, ...band } = runBandOf(id, bd, cache)
  return band
}

/** The Version of <root>/.bd/rubric.md as an integer, or null when it can't be read. */
export function rubricVersion(root) {
  try {
    const m = /^Version:\s*(\d+)\s*$/m.exec(readFileSync(join(root, '.bd', 'rubric.md'), 'utf8'))
    return m ? Number(m[1]) : null
  } catch {
    return null
  }
}

// ---------- report ----------
const side = (p) => ({ label: p.label, model: p.model, effort: p.effort, findings: p.findings.length })

// One pair as JSON: its run, source, band, rubric version and per-side counts, never claims or prompts.
const entry = (pair, { run, workflow, wf, source, band, bandSource, rubric }) => {
  const m = matchFindings(pair.a.findings, pair.b.findings)
  return {
    run,
    workflow,
    wf,
    source,
    kind: pair.a.kind,
    round: pair.a.round,
    band,
    bandSource,
    rubric,
    prompt: pair.prompt,
    a: side(pair.a),
    b: side(pair.b),
    matched: m.matches.length,
    aOnly: m.aOnly.length,
    bOnly: m.bOnly.length,
  }
}

/**
 * The report over Copilot runs (journals, as readJournals gives them), Claude Code workflow journals (claude, as
 * readClaudeJournals gives them) and hand-run groups (hand, from readHandPasses), with bands from bd: counts, JSON-safe
 * pairs (labels, models, efforts, counts and the run reviewed, never claims or prompts) and rows for both views.
 * Copilot pairs get source 'shadow', Claude Code workflow pairs 'claude-shadow', hand-run pairs 'hand-shadow', each
 * with its own band (the real pass's issue, else the shadow's). A hand-run pair's verdicts come from the Finding bugs
 * under the review step of the change run its band came from (runBandOf): each pass's blocker and serious findings
 * matched to those bugs (matchBugs), the pair's verdict map the union of both passes', the real pass's verdict winning
 * where both have one for a key, so observe() reads them as it reads validators. handVerdicts counts the distinct
 * hand-run findings that got a verdict, a pass in several pairs counted once.
 */
export function report({ journals = [], claude = [], hand = [], bd, currentRubric = null }) {
  const cache = new Map()
  const pairs = []
  const observations = []
  const skipped = { differentPrompt: 0, failed: 0, noShadow: 0 }
  const unknown = { band: 'unknown', source: null, rubric: null }
  let passes = 0
  let failed = 0
  let handPasses = 0
  let handFailed = 0
  const workflowRun = (ps, { verdictsOf, args, workflow, wf, source }) => {
    passes += ps.length
    failed += ps.filter((p) => p.failed).length
    const got = pairPasses(ps)
    skipped.differentPrompt += got.skipped.differentPrompt
    skipped.failed += got.skipped.failed
    // Only journals with pairs need validators and a band, which saves a bd call per other workflow.
    if (!got.pairs.length) return
    const verdicts = verdictsOf()
    const run = runOf(args, ps.map((p) => p.prompt))
    const { band, source: bandSource, rubric } = run ? bandOf(run, bd, cache) : unknown
    for (const pair of got.pairs) {
      observations.push(...observe(pair, band, verdicts, rubric))
      pairs.push(entry(pair, { run, workflow, wf, source, band, bandSource, rubric }))
    }
  }
  for (const j of journals) workflowRun(passesOf(j), { verdictsOf: () => validatorsOf(j), args: j.args, workflow: j.workflow, wf: j.run, source: 'shadow' })
  for (const j of claude) workflowRun(claudePassesOf(j), { verdictsOf: () => claudeValidatorsOf(j), args: j.args, workflow: j.workflow, wf: j.wf, source: 'claude-shadow' })
  // Each hand-run pass's verdicts from its change run's Finding bugs, computed once per pass and run (byRun), and the
  // keys of its findings that got one (keys), so a pass in several pairs counts each of its findings once in handVerdicts.
  const passVerdicts = new Map()
  const verdictsOfPass = (p, changeRun) => {
    let seen = passVerdicts.get(p)
    if (!seen) passVerdicts.set(p, (seen = { byRun: new Map(), keys: new Set() }))
    if (!seen.byRun.has(changeRun)) {
      const got = matchBugs(p.findings, changeRun ? verdictsFromBugs(changeRun, bd, cache) : [])
      seen.byRun.set(changeRun, got)
      for (const k of got.keys()) seen.keys.add(k)
    }
    return seen.byRun.get(changeRun)
  }
  for (const g of hand) {
    handPasses += g.passes.length
    handFailed += g.passes.filter((p) => p.failed).length
    const got = pairHandPasses(g.passes)
    skipped.noShadow += got.skipped.noShadow
    skipped.failed += got.skipped.failed
    for (const pair of got.pairs) {
      const run = pair.a.issue ?? pair.b.issue ?? null
      const { band, source, rubric, run: changeRun } = run ? runBandOf(run, bd, cache) : { ...unknown, run: null }
      // Shadow first, so the real pass's verdict wins on a key collision and the shadow fills only keys the real pass lacks.
      const verdicts = new Map([...verdictsOfPass(pair.b, changeRun), ...verdictsOfPass(pair.a, changeRun)])
      observations.push(...observe(pair, band, verdicts, rubric))
      pairs.push(entry(pair, { run, workflow: 'hand', wf: g.wf, source: 'hand-shadow', band, bandSource: source, rubric }))
    }
  }
  const handVerdicts = [...passVerdicts.values()].reduce((n, { keys }) => n + keys.size, 0)
  return {
    journals: journals.length,
    claudeJournals: claude.length,
    hand: hand.length,
    passes,
    failed,
    handPasses,
    handFailed,
    handVerdicts,
    currentRubric,
    pairs,
    skipped,
    rows: aggregate(observations),
  }
}

// ---------- CLI ----------
const firstLine = (e) => (e.stderr?.toString().trim() || e.message).split('\n')[0]

/** The main checkout: the directory holding git's common dir, else the working directory. */
function mainCheckout() {
  try {
    const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
    return dirname(common.trim())
  } catch {
    return process.cwd()
  }
}

function main(argv) {
  const opt = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined)
  const sessionsDir = opt('--sessions') ?? join(process.env.COPILOT_HOME ?? join(homedir(), '.copilot'), 'session-state')
  const projectsDir = opt('--projects') ?? join(process.env.CLAUDE_CONFIG_DIR ?? join(homedir(), '.claude'), 'projects')
  const root = opt('--root') ?? mainCheckout()
  const run = bdRunner(root)
  // An issue bd doesn't know just has no band. Any other failure means bd itself is unavailable: say so once and stop
  // asking, so every band left is 'unknown' rather than a wait per run.
  let down = false
  const bd = (args) => {
    if (down) throw new Error('bd unavailable')
    try {
      return run(args)
    } catch (e) {
      if (/not_found|not found/i.test(`${e.stderr ?? ''}${e.message}`)) throw e
      down = true
      process.stderr.write(`reviewer-catch: bd unavailable, bands unknown: ${firstLine(e)}\n`)
      throw e
    }
  }
  const result = report({
    journals: readJournals(sessionsDir),
    claude: readClaudeJournals(projectsDir, root),
    hand: readHandPasses(projectsDir, root),
    bd,
    currentRubric: rubricVersion(root),
  })
  process.stdout.write(`${argv.includes('--json') ? JSON.stringify(result, null, 2) : render(result)}\n`)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2))
  } catch (e) {
    process.stderr.write(`reviewer-catch: ${firstLine(e)}\n`)
    process.exitCode = 1
  }
}
