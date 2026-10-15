#!/usr/bin/env node
// How often each reviewer model and effort catches what a paired pass over the same diff and prompt found, by the
// complexity band of the bd run it reviewed: the evidence for which model and effort the reviewer roles get.
//
//   node .github/scripts/reviewer-catch.mjs [--root <checkout>] [--sessions <dir>] [--json]
//
// Reads the Copilot CLI sessions on this machine (<sessions>/<session>/): the review and validate agents that
// plan-implement-review recorded in files/workflow-agents/<run id>.jsonl (their label, a hash of their prompt, their
// result), and events.jsonl for the model and reasoning effort each agent actually ran with; and `bd show` for
// complexity. Copilot keeps neither a workflow agent's prompt nor its result, which is why the extension records them.
// Read-only: it writes no file and nothing to bd.
//
// Passes. A review agent labelled review:<kind>:r<N> is a real pass, review:<kind>:r<N>@shadow:<model>-<effort> a shadow
// (plan-implement-review's shadowReview). Model and effort come from the session's subagent events, else what the workflow
// asked for. What can't be read is 'unknown', never guessed. A pass without a result failed and is never paired.
//
// Pairing. Within one workflow run, kind and round, every shadow pairs with the real pass. A pair counts only when both
// prompts hash alike (same diff, same instructions); the extension gives both the same prompt, so a differing hash is
// skipped as differentPrompt.
//
// Matching. Findings are matched one-to-one, greedily by best score. Both must name a file with the same basename. When
// both have a line, they match if the lines are at most 5 apart (score 1 - |delta|/10); when either lacks one, they
// match if the Jaccard similarity of their claims' lowercase word tokens (3+ characters) is at least 0.3. Validator
// verdicts join to findings by file basename plus the whitespace-collapsed claim text of the finding each validator
// was given.
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
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bdRunner, readJsonl, sessionEvents, subagentsOf } from './trace-run.mjs'

// ---------- labels ----------
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

// ---------- passes ----------
/**
 * The review passes of one journal ({ run, agents: [{ label, model, effort, prompt, result }] }): label fields, model,
 * effort, prompt hash and findings, or failed when the agent left no readable findings.
 */
export function passesOf(journal) {
  return journal.agents.flatMap((a) => {
    const label = parseLabel(a.label)
    if (!label) return []
    const known = (x) => (x && x !== 'unknown' ? x : null)
    const findings = Array.isArray(a.result?.findings) ? a.result.findings : null
    return [
      {
        journal: journal.run,
        label: a.label,
        ...label,
        // A shadow's label records the model and effort it was started with, for when the session log is not here.
        model: known(a.model) ?? label.shadow?.model ?? 'unknown',
        effort: known(a.effort) ?? label.shadow?.effort ?? 'unknown',
        prompt: a.prompt ?? null,
        findings,
        failed: findings == null,
      },
    ]
  })
}

// ---------- verdicts ----------
const basename = (file) => String(file ?? '').split(/[\\/]/).pop()
const collapse = (s) => String(s ?? '').replace(/\s+/g, ' ').trim()
const keyOf = (file, claim) => `${basename(file)}\0${collapse(claim)}`

/** Verdicts of the journal's validators, keyed by file basename and collapsed claim text. */
export function validatorsOf(journal) {
  const verdicts = new Map()
  for (const a of journal.agents) {
    if (!a.label?.startsWith('validate:') || typeof a.result?.valid !== 'boolean' || !a.finding) continue
    verdicts.set(keyOf(a.finding.file, a.finding.claim), { valid: a.result.valid, blocking: Boolean(a.result.blocking) })
  }
  return verdicts
}

/** The verdict on a finding, or null when no validator judged it. */
export const verdictOf = (finding, verdicts) => verdicts.get(keyOf(finding.file, finding.claim)) ?? null

// ---------- pairing ----------
/** Pairs of passes over the same diff and prompt: { pairs: [{ source, a, b }], skipped }. a is the real pass. */
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
        else if (a.prompt !== b.prompt) skipped.differentPrompt++
        else pairs.push({ source: 'shadow', a, b })
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
  candidates.sort((x, y) => y.score - x.score || x.i - y.i || x.j - y.j)
  const usedA = new Set()
  const usedB = new Set()
  const matches = []
  for (const { i, j } of candidates)
    if (!usedA.has(i) && !usedB.has(j)) {
      usedA.add(i)
      usedB.add(j)
      matches.push([i, j])
    }
  return {
    matches,
    aOnly: as.map((_, i) => i).filter((i) => !usedA.has(i)),
    bOnly: bs.map((_, j) => j).filter((j) => !usedB.has(j)),
  }
}

// ---------- aggregate ----------
/** The two observations of a pair, one per side, each counted against the other side's model and effort. */
export function observe(pair, band, verdicts) {
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

const bandOrder = (x, y) => {
  const nx = typeof x === 'number' ? x : Number.POSITIVE_INFINITY
  const ny = typeof y === 'number' ? y : Number.POSITIVE_INFINITY
  return nx - ny || String(x).localeCompare(String(y))
}

/**
 * Observations summed into rows by band, model/effort and partner model/effort, for both views.
 * A row where model equals vs has sameLevel true, catch null and agreement = matched / raised (null if raised is 0).
 */
export function aggregate(observations) {
  const view = (name) => {
    const rows = new Map()
    const pairsOf = new Map() // key -> Set of pair identities, kept out of the rows
    for (const o of observations) {
      const modelEffort = `${o.model}/${o.effort}`
      const key = `${o.band}\0${modelEffort}\0${o.vs}`
      const row = rows.get(key) ?? {
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
      .toSorted((x, y) => bandOrder(x.band, y.band) || x.model.localeCompare(y.model) || x.vs.localeCompare(y.vs))
  }
  return { all: view('all'), validated: view('validated') }
}

// ---------- render ----------
const pct = (x) => (x == null ? '–' : `${Math.round(x * 100)}%`)
const table = (head, rows) => [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.join(' | ')} |`)].join('\n')
const rowsTable = (rows) =>
  rows.length
    ? table(
        ['band', 'model/effort', 'vs', 'pairs', 'raised', 'matched', 'missed', 'catch', 'agree', 'thin'],
        rows.map((r) => [r.band, r.model, r.vs, r.pairs, r.raised, r.matched, r.missed, pct(r.catch), pct(r.agreement), r.thin ? 'thin' : '']),
      )
    : 'No pairs.'

/**
 * The report as markdown. data: { journals, passes, failed, pairs: [{ band }], skipped, rows: { all,
 * validated } }. Prints only counts, labels, models, efforts and bands: never claims, paths or prompts.
 */
export function render(data) {
  const unverified = data.rows.validated.reduce((n, r) => n + r.unverified, 0)
  return [
    `# Reviewer catch rate`,
    ``,
    `${data.journals} journals, ${data.passes} review passes (${data.failed} failed). ` +
      `${data.pairs.length} pairs of real vs shadow passes. ` +
      `Skipped: ${data.skipped.differentPrompt} with different prompts, ${data.skipped.failed} with a failed side. ` +
      `${data.pairs.filter((p) => p.band === 'unknown').length} with the band unknown.`,
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
    `Each row is one side of its pairs: its model/effort against its partner's (vs), in the complexity band of the run reviewed. ` +
      `Findings match one-to-one on the same file basename, with lines at most 5 apart, or similar claims when a line is missing. ` +
      `missed = the partner's findings this side did not raise; catch = raised / union, with union = raised + missed, summed over pairs. ` +
      `Where model/effort equals vs, both sides of each pair sum into one row, so catch would be 50% to 100% by construction; those rows show agree = matched / raised instead (matched counts each match once per side), and catch –. ` +
      `Thin rows have under 5 pairs.`,
  ].join('\n')
}

// ---------- journals ----------
const list = (dir) => (existsSync(dir) ? readdirSync(dir) : [])
const RUN_FILE = /^[0-9a-f-]{36}\.jsonl$/

/**
 * Every recorded workflow run on this machine: { run, workflow, args: { reviewStep, issue }, agents: [{ label, model,
 * effort, prompt, result, finding }] }. An agent's model and effort come from its subagent events (matched by workflow
 * run and label), else what the workflow asked for. A run resumed after a pause recorded its replayed agents again: each
 * label and prompt counts once, the last record standing.
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

// ---------- bands ----------
const ISSUE_ID = /^[a-z0-9.-]+$/

/** The bd issue a workflow worked on: its run record's reviewStep (as its run), else its issue. */
export function runOf(args) {
  if (typeof args?.reviewStep === 'string') return args.reviewStep.replace(/\.review$/, '')
  if (typeof args?.issue === 'string') return args.issue
  return null
}

/**
 * The complexity band of a bd issue (a playbook step counts as its run): { band, source }, with source 'confirmed',
 * 'judged' or 'estimate', or band 'unknown' and source null. bd(args) returns parsed `bd ... --json` output; each id is
 * shown at most once per cache, and an id that isn't a plain issue id never reaches bd.
 */
export function bandOf(id, bd, cache = new Map()) {
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
  let issue = show(id)
  const playbook = issue?.metadata?.playbook
  if (playbook?.role === 'step') issue = show(playbook.run)
  const md = issue?.metadata
  if (md?.score?.complexity != null) return { band: md.score.complexity, source: 'confirmed' }
  if (md?.score_judge?.complexity != null) return { band: md.score_judge.complexity, source: 'judged' }
  if (md?.complexity_estimate?.score != null) return { band: md.complexity_estimate.score, source: 'estimate' }
  return { band: 'unknown', source: null }
}

// ---------- report ----------
const side = (p) => ({ label: p.label, model: p.model, effort: p.effort, findings: p.findings.length })

/**
 * The report over journals (as readJournals gives them), with bands from bd: counts, JSON-safe pairs (labels,
 * models, efforts and counts, never claims or prompts) and rows for both views.
 */
export function report({ journals, bd }) {
  const cache = new Map()
  const pairs = []
  const observations = []
  const skipped = { differentPrompt: 0, failed: 0 }
  let passes = 0
  let failed = 0
  for (const journal of journals) {
    const ps = passesOf(journal)
    passes += ps.length
    failed += ps.filter((p) => p.failed).length
    const got = pairPasses(ps)
    skipped.differentPrompt += got.skipped.differentPrompt
    skipped.failed += got.skipped.failed
    // Only journals with pairs need validators and a band, which saves a bd call per other workflow.
    if (!got.pairs.length) continue
    const verdicts = validatorsOf(journal)
    const run = runOf(journal.args)
    const { band, source } = run ? bandOf(run, bd, cache) : { band: 'unknown', source: null }
    for (const pair of got.pairs) {
      observations.push(...observe(pair, band, verdicts))
      const m = matchFindings(pair.a.findings, pair.b.findings)
      pairs.push({
        run,
        workflow: journal.workflow,
        wf: journal.run,
        source: pair.source,
        kind: pair.a.kind,
        round: pair.a.round,
        band,
        bandSource: source,
        a: side(pair.a),
        b: side(pair.b),
        matched: m.matches.length,
        aOnly: m.aOnly.length,
        bOnly: m.bOnly.length,
      })
    }
  }
  return { journals: journals.length, passes, failed, pairs, skipped, rows: aggregate(observations) }
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
  const result = report({ journals: readJournals(sessionsDir), bd })
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
