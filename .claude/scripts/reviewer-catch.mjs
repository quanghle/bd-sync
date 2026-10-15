#!/usr/bin/env node
// How often each reviewer model and effort catches what a paired pass over the same diff and prompt found, by the
// complexity band of the bd run it reviewed: the evidence for which model and effort the reviewer roles get.
//
//   node .claude/scripts/reviewer-catch.mjs [--root <checkout>] [--projects <dir>] [--json]
//
// Reads this project's workflow journals on this machine (<projects>/<encoded checkout or its worktrees>/<session>/
// subagents/workflows/<wf>/journal.jsonl), each agent's meta and transcript beside them, the workflow's run record, and
// `bd show` for complexity. Read-only: it writes no file and nothing to bd.
//
// Passes. A review agent labelled review:<kind>:r<N> (or r<N>@<level>, an escalated retry) is a cheap pass,
// review:<kind>:confirm-r<N>@strong a confirmation, review:<kind>:r<N>@shadow:<model>-<effort> a shadow (plan-implement-
// review's shadowReview). Model comes from the agent's meta, else its transcript's requests, as a class; effort from the
// transcript. What can't be read is 'unknown', never guessed. A pass without a result failed and is never paired.
//
// Prompt. An agent's prompt is its computed task: the leading user entry (before the first assistant entry) that starts
// with '[Workflow harness — computed task]'. Many transcripts open with a '[Workflow harness — user request]' relay that
// is the same for every agent of a workflow, so it says nothing about the pass. Without a computed-task entry the
// leading user entries are joined; without a transcript the prompt is unknown.
//
// Pairing. Within one journal, kind and round, every confirmation pairs with every cheap pass (escalated ones too), and
// every shadow with the plain cheap pass. A pair counts only when both prompts are identical (same diff, same
// instructions): a focused re-review against a full confirmation is skipped as differentPrompt. A pair whose prompt
// can't be read is kept as 'unchecked'.
//
// Matching. Findings are matched one-to-one, greedily by best score. Both must name a file with the same basename. When
// both have a line, they match if the lines are at most 5 apart (score 1 - |delta|/10); when either lacks one, they
// match if the Jaccard similarity of their claims' lowercase word tokens (3+ characters) is at least 0.3. Validator
// verdicts join to findings by file basename plus the whitespace-collapsed claim text in the validator's prompt.
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
// Bias. Confirmation passes ran only where the workflow asked for one (escalation, an uncertain cheap pass, a tier that
// confirms), so cheap-vs-confirm pairs are not a random sample of reviews; shadow pairs are the unbiased comparison.
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bdRunner, readJson, readJsonl, requestsOf } from './trace-run.mjs'

// ---------- prompts ----------
export const COMPUTED_TASK = '[Workflow harness — computed task]'

/** The text of a transcript entry: its string content, or its text blocks joined. */
export function textOf(entry) {
  const c = entry?.message?.content
  if (typeof c === 'string') return c
  return Array.isArray(c) ? c.filter((b) => b?.type === 'text' && typeof b.text === 'string').map((b) => b.text).join('\n') : ''
}

/** An agent's prompt from its transcript entries: the computed task, else the leading user entries, else null. */
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

// ---------- labels and facts ----------
const EFFORTS = new Set(['low', 'medium', 'high', 'xhigh', 'max'])
const LABEL = /^review:([a-z0-9-]+):(confirm-)?r(\d+)(?:@(.+))?$/

/** A review pass's label parsed, or null for any other agent. */
export function parseLabel(label) {
  const m = LABEL.exec(label ?? '')
  if (!m) return null
  const [, kind, confirm, round, suffix] = m
  const base = { kind, round: Number(round) }
  if (confirm) return { ...base, type: 'confirm', ...(suffix ? { level: suffix } : {}) }
  if (suffix?.startsWith('shadow:')) {
    const spec = suffix.slice('shadow:'.length)
    const at = spec.lastIndexOf('-')
    const model = spec.slice(0, at)
    const effort = spec.slice(at + 1)
    if (at > 0 && EFFORTS.has(effort)) return { ...base, type: 'shadow', shadow: { model, effort } }
    return null
  }
  return { ...base, type: 'cheap', ...(suffix ? { level: suffix } : {}) }
}

/** A model id as its class (haiku, sonnet, opus, fable), else the id itself, else 'unknown'. */
export function modelClass(id) {
  if (!id) return 'unknown'
  return /haiku|sonnet|opus|fable/.exec(id)?.[0] ?? id
}

const mode = (xs) => {
  const counts = new Map()
  for (const x of xs) counts.set(x, (counts.get(x) ?? 0) + 1)
  let best = null
  for (const [x, c] of counts) if (best == null || c > counts.get(best)) best = x
  return best
}

/** Model class, effort and prompt of an agent from its meta (or null) and transcript entries (or null). */
export function agentFacts(meta, entries) {
  const requests = entries?.length ? requestsOf(entries) : []
  return {
    model: modelClass(meta?.model ?? mode(requests.map((r) => r.model))),
    effort: mode(requests.map((r) => r.effort).filter((e) => e && e !== 'unknown')) ?? 'unknown',
    prompt: promptOf(entries),
  }
}

// ---------- passes ----------
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
 * The review passes of one journal ({ wf, entries }): label fields, model, effort, prompt and findings, or failed when
 * the agent left no readable findings. factsOf(agentId) gives agentFacts for the agent.
 */
export function passesOf(journal, factsOf) {
  return agentsOf(journal.entries, (l) => parseLabel(l) != null).map(({ started, result }) => {
    const label = parseLabel(started.label)
    const facts = factsOf(started.agentId) ?? { model: 'unknown', effort: 'unknown', prompt: null }
    // A shadow's label records the model and effort it was started with; the transcript, when readable, wins.
    const model = facts.model !== 'unknown' ? facts.model : label.shadow ? modelClass(label.shadow.model) : 'unknown'
    const effort = facts.effort !== 'unknown' ? facts.effort : (label.shadow?.effort ?? 'unknown')
    const findings = Array.isArray(result?.findings) ? result.findings : null
    return {
      journal: journal.wf,
      agentId: started.agentId,
      label: started.label,
      ...label,
      model,
      effort,
      prompt: facts.prompt,
      findings,
      failed: findings == null,
    }
  })
}

// ---------- verdicts ----------
const basename = (file) => String(file ?? '').split(/[\\/]/).pop()
const collapse = (s) => String(s ?? '').replace(/\s+/g, ' ').trim()
const keyOf = (file, claim) => `${basename(file)}\0${collapse(claim)}`

/** The finding a validator was given, from its prompt: { file, line, claim }, or null. */
function findingIn(prompt) {
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

/** Verdicts of the journal's validators, keyed by file basename and collapsed claim text. */
export function validatorsOf(journal, factsOf) {
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

// ---------- pairing ----------
/** Pairs of passes over the same diff and prompt: { pairs: [{ source, a, b, prompt }], skipped }. a is the cheap or real pass. */
export function pairPasses(passes) {
  const groups = new Map()
  for (const p of passes) {
    const key = `${p.journal}:${p.kind}:${p.round}`
    groups.set(key, [...(groups.get(key) ?? []), p])
  }
  const pairs = []
  const skipped = { differentPrompt: 0, failed: 0 }
  const pair = (source, a, b) => {
    if (a.failed || b.failed) skipped.failed++
    else if (a.prompt == null || b.prompt == null) pairs.push({ source, a, b, prompt: 'unchecked' })
    else if (a.prompt === b.prompt) pairs.push({ source, a, b, prompt: 'same' })
    else skipped.differentPrompt++
  }
  for (const group of groups.values()) {
    const cheap = group.filter((p) => p.type === 'cheap')
    for (const b of group.filter((p) => p.type === 'confirm')) for (const a of cheap) pair('confirm', a, b)
    for (const b of group.filter((p) => p.type === 'shadow')) for (const a of cheap.filter((p) => !p.level)) pair('shadow', a, b)
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
 * The report as markdown. data: { journals, passes, failed, pairs: [{ source, prompt, band }], skipped, rows: { all,
 * validated } }. Prints only counts, labels, models, efforts and bands: never claims, paths or prompts.
 */
export function render(data) {
  const bySource = (s) => data.pairs.filter((p) => p.source === s).length
  const unverified = data.rows.validated.reduce((n, r) => n + r.unverified, 0)
  return [
    `# Reviewer catch rate`,
    ``,
    `${data.journals} journals, ${data.passes} review passes (${data.failed} failed). ` +
      `${data.pairs.length} pairs: ${bySource('confirm')} cheap vs confirm, ${bySource('shadow')} real vs shadow. ` +
      `Skipped: ${data.skipped.differentPrompt} with different prompts, ${data.skipped.failed} with a failed side. ` +
      `${data.pairs.filter((p) => p.prompt === 'unchecked').length} with the prompt unchecked, ` +
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
      `Thin rows have under 5 pairs. Confirmations ran only where the workflow asked for one, so cheap-vs-confirm rows are a biased sample; shadow rows are not.`,
  ].join('\n')
}

// ---------- journals ----------
const list = (dir) => (existsSync(dir) ? readdirSync(dir) : [])

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
 * Every workflow journal of this project: { wf, workflow, args, entries, factsOf }. factsOf(agentId) reads the agent's
 * meta and transcript beside the journal, once, into agentFacts.
 */
export function readJournals(projectsDir, root) {
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
        return [{ wf, workflow: record?.workflowName ?? null, args: args && typeof args === 'object' ? args : null, entries: readJsonl(file), factsOf }]
      })
    }),
  )
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
 * The report over journals ({ wf, workflow, args, entries, factsOf }), with bands from bd: counts, JSON-safe pairs (labels,
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
    const ps = passesOf(journal, journal.factsOf)
    passes += ps.length
    failed += ps.filter((p) => p.failed).length
    const got = pairPasses(ps)
    skipped.differentPrompt += got.skipped.differentPrompt
    skipped.failed += got.skipped.failed
    // Only journals with pairs need validators and a band, which saves a bd call per other workflow.
    if (!got.pairs.length) continue
    const verdicts = validatorsOf(journal, journal.factsOf)
    const run = runOf(journal.args, ps.map((p) => p.prompt))
    const { band, source } = run ? bandOf(run, bd, cache) : { band: 'unknown', source: null }
    for (const pair of got.pairs) {
      observations.push(...observe(pair, band, verdicts))
      const m = matchFindings(pair.a.findings, pair.b.findings)
      pairs.push({
        run,
        workflow: journal.workflow,
        wf: journal.wf,
        source: pair.source,
        kind: pair.a.kind,
        round: pair.a.round,
        band,
        bandSource: source,
        prompt: pair.prompt,
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
  const result = report({ journals: readJournals(projectsDir, root), bd })
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
