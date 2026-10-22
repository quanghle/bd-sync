#!/usr/bin/env node
// The evidence for changing how complexity is judged and which model and effort each role gets: every change playbook
// run's complexity estimate and judged complexity, its score, the findings its review filed, and who did the work with
// which model and effort at what cost (Copilot AI credits as USD, Claude Code tokens at list prices) and for how long: agent busy time (model requests and the tools they ran,
// per agent and step) next to cost, each step's elapsed time, and the human wait at gates (armed to resolved), apart.
//
//   node .github/scripts/calibrate.mjs [--root <checkout>] [--sessions <dir>] [--projects <dir>] [--json] [--write]
//
// Read-only unless --write, which stores a backfilled trace as the work metadata of a run that has none. Traces come from
// the run's work metadata, else from trace-run on this machine's Copilot session logs and Claude Code transcripts. Costs are the AI credits
// Copilot logged per request (1 credit = $0.01), else, for Claude Code requests, notional list prices from prices.json;
// a request with neither (an older Copilot trace, a model the table lacks) is unpriced. Timing
// (step elapsed times, gate waits) is read from the bd list at report time, not from the stored trace, which is written
// before the run's last steps and its score gate close. The complexity tables (estimate vs judged, score, score by coder,
// and cost and time by complexity) are per rubric version (.bd/rubric.md's Version, recorded with each estimate and score):
// a run counts under its judged score's version, and an estimate/judged pair of different versions is counted apart as mixed.
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { canonicalModel, ROLE_PREFIXES } from './reviewer-catch.mjs'
import { activeMs, bdRunner, fmtDuration, logDirs, readRecord, stepFrom, timingOf, trace } from './trace-run.mjs'

// ---------- roles ----------
// What an agent did, from its trace label: 'main', a workflow's '<workflow>:<role>[:...]', or a subagent's
// '<type>: <description>' (Claude Code's agentType, Copilot's agentName). A subagent's role comes from its description's
// role prefix (AGENTS.md; the words are reviewer-catch.mjs's ROLE_PREFIXES), else a label naming review. A heuristic over
// labels the callers chose, so 'other' is a real answer.
const WORKFLOW_ROLES = [
  [/^(coder|implement)\b/, 'coder'],
  [/^review\b/, 'reviewer'],
  [/^validate\b/, 'validator'],
  [/^planner\b|^critic\b|^triage\b/, 'planner'],
  [/^(gate|record|heartbeat|claim|setup|bd|trace)\b/, 'mechanical'],
  [/^judge\b/, 'judge'],
]
// The optional group skips one agent type token: one containing '-' or ':' (general-purpose, code-review, plugin:agent) or a
// known single-word one (Claude Code's Explore and Plan, Copilot's task and explore). So neither a role word later in the
// description nor an ordinary leading word ('Fix: coder: x') counts.
const SINGLE_WORD_TYPES = ['Explore', 'Plan', 'task']
const AGENT_TYPE = `(?:[\\w.]*[-:][\\w.:-]*|${SINGLE_WORD_TYPES.join('|')})`
const ROLE_PREFIX = new RegExp(`^(?:${AGENT_TYPE}: )?(${ROLE_PREFIXES.join('|')}):`, 'i')
export function roleOf(agent) {
  if (agent.kind === 'main') return 'main'
  if (agent.kind === 'workflow') {
    const role = agent.label.split(':')[1] ?? ''
    return WORKFLOW_ROLES.find(([re]) => re.test(role))?.[1] ?? 'other'
  }
  const prefix = ROLE_PREFIX.exec(agent.label)?.[1]
  if (prefix) return prefix.toLowerCase()
  return /review/i.test(agent.label) ? 'reviewer' : 'other'
}

/**
 * A run's coder: the model and effort with the most requests among its workflow coder agents (coder/implement roles), or,
 * when it has none, among its `coder:` subagents; null when untraced or there are none. A controller's `coder:` subagent
 * (a closer merging worktrees) never outvotes the workflow's own coders.
 */
export function coderOf(work) {
  const coders = (work?.steps ?? []).flatMap((s) => s.agents).filter((x) => roleOf(x) === 'coder')
  const workflow = coders.filter((a) => a.kind === 'workflow')
  const pool = workflow.length ? workflow : coders
  const by = new Map()
  for (const a of pool) {
    // One name per model across harnesses (Claude Code's claude-opus-5-5, Copilot's claude-opus-5.5).
    const model = canonicalModel(a.model)
    const key = `${model}\0${a.effort}`
    const x = by.get(key) ?? { model, effort: a.effort, requests: 0 }
    x.requests += a.requests
    by.set(key, x)
  }
  let best = null
  for (const x of by.values()) if (!best || x.requests > best.requests) best = x
  return best
}

/**
 * A run's planner: the model and effort with the most requests among its workflow planner-role agents (planner, critic and
 * triage roles), or, when it has none, among its `planner:` subagents (such as the controller's pre-step planner, which the
 * planner effort exploration does not set); null when untraced or there are none.
 */
export function plannerOf(work) {
  const planners = (work?.steps ?? []).flatMap((s) => s.agents).filter((x) => roleOf(x) === 'planner')
  const workflow = planners.filter((a) => a.kind === 'workflow')
  const pool = workflow.length ? workflow : planners
  const by = new Map()
  for (const a of pool) {
    // One name per model across harnesses (Claude Code's claude-opus-5-5, Copilot's claude-opus-5.5).
    const model = canonicalModel(a.model)
    const key = `${model}\0${a.effort}`
    const x = by.get(key) ?? { model, effort: a.effort, requests: 0 }
    x.requests += a.requests
    by.set(key, x)
  }
  let best = null
  for (const x of by.values()) if (!best || x.requests > best.requests) best = x
  return best
}

// ---------- cost ----------
const USD_PER_CREDIT = 0.01
const NANO = 1e9

/** List prices for Claude Code requests (prices.json): USD per million tokens per model, and the cache write multipliers. */
export const PRICES = JSON.parse(readFileSync(fileURLToPath(new URL('./prices.json', import.meta.url)), 'utf8'))

/**
 * USD for an agent's token count: the AI credits Copilot logged (nano_aiu), else the model's list prices (a Claude Code
 * agent: input, output, cache reads, and cache writes at input x the 5-minute or, for cache_write_1h, the 1-hour
 * multiplier); null when neither applies (an older Copilot trace, a model the table lacks). Output a transcript did not
 * record (output_unknown) costs nothing here and is counted apart.
 */
export function costOf(tokens, model, prices = PRICES) {
  if (typeof tokens?.nano_aiu === 'number') return (tokens.nano_aiu / NANO) * USD_PER_CREDIT
  const p = model ? prices.models?.[model] : undefined
  if (!tokens || !p) return null
  const hour = tokens.cache_write_1h ?? 0
  const five = Math.max(0, (tokens.cache_write ?? 0) - hour)
  return (
    ((tokens.input ?? 0) * p.input +
      (tokens.output ?? 0) * p.output +
      (tokens.cache_read ?? 0) * p.cache_read +
      five * p.input * prices.cache_write_multiplier +
      hour * p.input * (prices.cache_write_1h_multiplier ?? prices.cache_write_multiplier)) /
    1e6
  )
}

/** Why a trace can't stand for the run's work, or null when it can. */
export function untracedWhy(work) {
  if (!work.sessions.length) return work.missing.length ? 'sessions not on this machine' : 'no agent sessions'
  if (!work.steps.length) return `no requests inside the run's step windows (${work.outside_requests} outside)`
  return null
}

// ---------- join ----------
const isDuplicate = (issue) => /^duplicate of /i.test(issue.close_reason ?? '')
const severityOf = (issue) => (issue.labels ?? []).find((l) => l.startsWith('severity:'))?.slice('severity:'.length)

/**
 * One row per change playbook run.
 * issues: every issue (bd list --all); followUpsOf(reviewStepId): ids discovered from it, or null when they couldn't be
 * read; traceOf(run): { work, why }, a trace or null plus why.
 */
export function joinRuns(issues, { followUpsOf, traceOf }) {
  const byId = new Map(issues.map((i) => [i.id, i]))
  return issues
    .filter((i) => i.metadata?.playbook?.role === 'run' && i.metadata.playbook.name === 'change')
    .toSorted((a, b) => (a.created_at ?? '').localeCompare(b.created_at ?? ''))
    .map((run) => {
      const md = run.metadata
      const review = `${run.id}.review`
      const findings = issues.filter((i) => i.id.startsWith(`${review}.`) && !isDuplicate(i))
      const dependents = followUpsOf(review)
      const followUps = dependents && dependents.map((id) => byId.get(id)).filter((i) => i && !isDuplicate(i))
      const { work, why } = md.work ? { work: md.work, why: null } : traceOf(run.id)
      const confirmed = md.score ?? null
      // Direct children only (nested findings aren't steps); a run without steps is its own only step.
      const children = issues.filter((i) => i.id.startsWith(`${run.id}.`) && !i.id.slice(run.id.length + 1).includes('.'))
      const timing = timingOf({ createdAt: run.created_at, steps: children.length ? children.map((c) => stepFrom(c)) : [stepFrom(run)] })
      return {
        id: run.id,
        tier: md.playbook.vars?.tier ?? null,
        status: run.status,
        task: md.playbook.vars?.task ?? run.title,
        estimate: md.complexity_estimate?.score ?? null,
        judged: md.score_judge?.complexity ?? null,
        confirmedComplexity: confirmed?.complexity ?? null,
        // The version of the score whose overall this row reports (no fallback to the judge's), and the estimate's.
        rubric: versionOf((confirmed ?? md.score_judge)?.rubric),
        estimateRubric: versionOf(md.complexity_estimate?.rubric),
        overall: confirmed?.overall ?? md.score_judge?.overall ?? null,
        // 'accepted': the judge's draft taken as the score with no person confirming it (by: judge).
        overallFrom: confirmed ? (confirmed.by === 'judge' ? 'accepted' : 'person') : md.score_judge ? 'judge' : null,
        findings: {
          serious: findings.filter((f) => ['blocker', 'serious'].includes(severityOf(f))).length,
          minor: findings.filter((f) => !['blocker', 'serious'].includes(severityOf(f))).length,
          followUps: followUps ? followUps.length : null,
        },
        created: run.created_at,
        work,
        // A backfilled trace of a run still open misses the work still to come.
        traced: work ? (md.work ? 'stored' : run.status === 'closed' ? 'backfilled' : 'partial') : null,
        untraced: work ? null : why,
        coder: coderOf(work),
        planner: plannerOf(work),
        // The exploration markers, e.g. { coder: 'sonnet/medium', rule: 'sha1-0-3' } (coder quota) and/or
        // { planner: 'opus/medium', plannerRule: 'sha1-2-0-3' } (planner effort exploration).
        exploration: md.exploration ?? null,
        timing,
      }
    })
}

// ---------- aggregate ----------
const complexityOf = (r) => r.confirmedComplexity ?? r.judged
const sum = (xs) => xs.reduce((a, b) => a + b, 0)
const mean = (xs) => (xs.length ? sum(xs) / xs.length : null)
const agentsOf = (r) => (r.work?.steps ?? []).flatMap((s) => s.agents)
const meanOf = (xs) => mean(xs.filter((x) => x != null))
// A rubric version is an integer; anything else in the free-form metadata is unknown (null).
const versionOf = (x) => (Number.isInteger(x) ? x : null)
const rubricOf = (r) => r.rubric ?? null
// Numeric versions ascending, unknown (null) last.
const byVersion = (a, b) => (a === b ? 0 : a == null ? 1 : b == null ? -1 : a - b)
// Runs grouped by (rubric version, complexity), sorted by version then complexity.
const byBand = (rs) => {
  const groups = new Map()
  for (const r of rs) {
    const key = `${rubricOf(r)}\0${complexityOf(r)}`
    const g = groups.get(key) ?? { rubric: rubricOf(r), complexity: complexityOf(r), runs: [] }
    g.runs.push(r)
    groups.set(key, g)
  }
  return [...groups.values()].toSorted((a, b) => byVersion(a.rubric, b.rubric) || a.complexity - b.complexity)
}
// The estimate gap (judged minus estimate) over runs that have both.
const gapOf = (rs) => {
  const gaps = rs.map((r) => complexityOf(r) - r.estimate)
  const gapBy = (key) =>
    Object.fromEntries(
      [...new Set(rs.map(key))].map((k) => {
        const g = rs.filter((r) => key(r) === k).map((r) => complexityOf(r) - r.estimate)
        return [k, { runs: g.length, mean: mean(g) }]
      }),
    )
  return {
    runs: gaps.length,
    mean: mean(gaps),
    distribution: [...new Set(gaps)].toSorted((a, b) => a - b).map((g) => [g, gaps.filter((x) => x === g).length]),
    byTier: gapBy((r) => r.tier),
  }
}

/**
 * Runs whose windows overlap in a shared session: a trace gives a run every request of its sessions inside its window, so
 * two such runs claim the same requests. Groups them and keeps the run with the most requests of each group for the
 * totals; another run is left out only when all its requests fall inside the kept one's window, so they are already
 * counted. A run that only partly overlaps stays in, and the group is flagged as double-counting the shared part.
 */
const spanOf = (r) => {
  const closes = (r.work?.steps ?? []).map((s) => s.closed_at)
  return closes.length ? [r.created ?? '', closes.reduce((a, b) => (b > a ? b : a))] : null
}
const requestsOf = (r) => sum(agentsOf(r).map((a) => a.requests))
// When a run's requests were actually made: from its agents' first to last request.
const activeOf = (r) => {
  const as = agentsOf(r)
  return [as.reduce((m, a) => (a.first < m ? a.first : m), '\uffff'), as.reduce((m, a) => (a.last > m ? a.last : m), '')]
}
export function overlaps(runs) {
  const traced = runs.map((r) => ({ r, span: spanOf(r), sessions: new Set((r.work?.sessions ?? []).map((s) => s.session)) })).filter((x) => x.span)
  const parent = new Map(traced.map((x) => [x.r.id, x.r.id]))
  const find = (id) => (parent.get(id) === id ? id : find(parent.get(id)))
  for (const [i, a] of traced.entries())
    for (const b of traced.slice(i + 1))
      if ([...a.sessions].some((s) => b.sessions.has(s)) && a.span[0] <= b.span[1] && b.span[0] <= a.span[1]) parent.set(find(b.r.id), find(a.r.id))
  const groups = new Map()
  for (const { r } of traced) groups.set(find(r.id), [...(groups.get(find(r.id)) ?? []), r])
  const result = { groups: [], excluded: new Set() }
  for (const g of groups.values())
    if (g.length > 1) {
      const kept = g.reduce((a, b) => (requestsOf(b) > requestsOf(a) ? b : a))
      const [from, to] = spanOf(kept)
      const inside = g.filter((r) => r !== kept && activeOf(r)[0] >= from && activeOf(r)[1] <= to)
      for (const r of inside) result.excluded.add(r.id)
      result.groups.push({ runs: g.map((r) => r.id), kept: kept.id, doubleCounted: g.length - 1 - inside.length > 0 })
    }
  return result
}

/** The joined runs reduced to what a rules review reads. */
export function aggregate(runs, prices = PRICES) {
  const overlap = overlaps(runs)
  const withGap = runs.filter((r) => r.estimate != null && complexityOf(r) != null)
  // An estimate counts against its judged complexity only under one rubric version; two unknowns agree (as unknown).
  const isMixed = (r) => (r.estimateRubric ?? null) !== rubricOf(r)
  const sameVersion = withGap.filter((r) => !isMixed(r))
  const gap = {
    mixed: withGap.filter(isMixed).length,
    byRubric: [...new Set(sameVersion.map(rubricOf))]
      .toSorted(byVersion)
      .map((v) => Object.assign({ rubric: v }, gapOf(sameVersion.filter((r) => rubricOf(r) === v)))),
  }
  // A mixed run still counts here, under its judged score's version.
  const scored = runs.filter((x) => complexityOf(x) != null && x.overall != null)
  const bands = byBand(scored).map((g) => ({
    rubric: g.rubric,
    complexity: g.complexity,
    runs: g.runs.length,
    overall: mean(g.runs.map((r) => r.overall)),
    serious: sum(g.runs.map((r) => r.findings.serious)),
  }))
  // Recomputed from the trace (not r.coder), so hand-built rows without joinRuns fields work too.
  const coders = new Map()
  for (const r of scored) {
    const c = coderOf(r.work)
    const label = c ? `${c.model}/${c.effort}` : r.work ? 'no coder agent' : 'untraced'
    const key = `${rubricOf(r)}\0${complexityOf(r)}\0${label}`
    const x = coders.get(key) ?? { rubric: rubricOf(r), complexity: complexityOf(r), coder: label, model: c?.model ?? null, effort: c?.effort ?? null, runs: 0, overall: [], serious: 0, exploration: 0 }
    x.runs++
    x.overall.push(r.overall)
    x.serious += r.findings.serious
    if (r.exploration?.coder) x.exploration++
    coders.set(key, x)
  }
  // The same for each run's planner, with the cost of its planner-role agents (the pre-step `planner:` subagent included)
  // per traced run; recomputed from the trace like coders.
  const planners = new Map()
  for (const r of scored) {
    const p = plannerOf(r.work)
    const label = p ? `${p.model}/${p.effort}` : r.work ? 'no planner agent' : 'untraced'
    const key = `${rubricOf(r)}\0${complexityOf(r)}\0${label}`
    const x = planners.get(key) ?? {
      rubric: rubricOf(r),
      complexity: complexityOf(r),
      planner: label,
      model: p?.model ?? null,
      effort: p?.effort ?? null,
      runs: 0,
      overall: [],
      serious: 0,
      plannerCost: [],
      exploration: 0,
    }
    x.runs++
    x.overall.push(r.overall)
    x.serious += r.findings.serious
    if (r.work) x.plannerCost.push(sum(agentsOf(r).filter((a) => roleOf(a) === 'planner').map((a) => costOf(a.tokens, a.model, prices) ?? 0)))
    if (r.exploration?.planner) x.exploration++
    planners.set(key, x)
  }
  const roles = new Map()
  const runCosts = new Map()
  for (const r of runs)
    for (const a of agentsOf(r)) {
      const c = costOf(a.tokens, a.model, prices)
      const unknown = a.tokens?.output_unknown ?? 0
      const rc = runCosts.get(r.id) ?? { cost: 0, unpriced: 0, outputUnknown: 0 }
      rc.outputUnknown += c == null ? 0 : unknown
      if (c == null) rc.unpriced += a.requests
      else rc.cost += c
      runCosts.set(r.id, rc)
      // An overlapping run's requests are already in the run kept for its group.
      if (overlap.excluded.has(r.id)) continue
      // One name per model across harnesses (Claude Code's claude-opus-5-5, Copilot's claude-opus-5.5); prices stay on the raw id.
      const model = canonicalModel(a.model)
      const key = `${roleOf(a)}\0${model}\0${a.effort}`
      const x = roles.get(key) ?? { role: roleOf(a), model, effort: a.effort, runs: new Set(), requests: 0, cost: 0, activeMs: 0, unpriced: 0, outputUnknown: 0 }
      x.runs.add(r.id)
      x.requests += a.requests
      x.activeMs += activeMs(a)
      x.outputUnknown += c == null ? 0 : unknown
      if (c == null) x.unpriced += a.requests
      else x.cost += c
      roles.set(key, x)
    }
  // Times use each run's own figures, as runCosts does; only the role totals leave overlapping runs out.
  const runTimes = Object.fromEntries(
    runs.map((r) => [
      r.id,
      { agentMs: r.work ? sum(agentsOf(r).map(activeMs)) : null, humanWaitMs: r.timing?.human_wait_ms ?? null, elapsedMs: r.timing?.elapsed_ms ?? null },
    ]),
  )
  const bandTimes = byBand(runs.filter((r) => complexityOf(r) != null)).map(({ rubric, complexity, runs: rs }) => {
    const tracedRuns = rs.filter((r) => r.work)
    return {
      rubric,
      complexity,
      runs: rs.length,
      traced: tracedRuns.length,
      cost: mean(tracedRuns.map((r) => runCosts.get(r.id)?.cost ?? 0)),
      agentMs: mean(tracedRuns.map((r) => runTimes[r.id].agentMs)),
      humanWaitMs: meanOf(rs.map((r) => runTimes[r.id].humanWaitMs)),
      elapsedMs: meanOf(rs.map((r) => runTimes[r.id].elapsedMs)),
    }
  })
  const stepTimes = new Map()
  for (const r of runs)
    for (const s of r.timing?.steps ?? []) {
      const key = s.step.startsWith(`${r.id}.`) ? s.step.slice(r.id.length + 1) : '(run)'
      const x = stepTimes.get(key) ?? { step: key, runs: 0, elapsed: [], traced: 0, agent: [] }
      x.runs++
      if (s.elapsed_ms != null) x.elapsed.push(s.elapsed_ms)
      if (r.work && !(r.work.open_steps ?? []).includes(s.step)) {
        x.traced++
        x.agent.push(sum((r.work.steps ?? []).filter((w) => w.step === s.step).flatMap((w) => w.agents.map(activeMs))))
      }
      stepTimes.set(key, x)
    }
  const mainPerRequest = runs
    .map((r) => {
      const thread = agentsOf(r).filter((a) => a.kind === 'main')
      const requests = sum(thread.map((a) => a.requests))
      const tokens = sum(thread.map((a) => a.tokens.input + a.tokens.cache_read + a.tokens.cache_write))
      return requests ? { id: r.id, requests, perRequest: Math.round(tokens / requests) } : null
    })
    .filter(Boolean)
  return {
    runs: runs.length,
    scored: runs.filter((r) => r.overall != null).length,
    traced: runs.filter((r) => r.work).length,
    gap,
    bands,
    coders: [...coders.values()]
      .map((x) => Object.assign(x, { overall: mean(x.overall) }))
      .toSorted((a, b) => byVersion(a.rubric, b.rubric) || a.complexity - b.complexity || a.coder.localeCompare(b.coder)),
    planners: [...planners.values()]
      .map((x) => Object.assign(x, { overall: mean(x.overall), plannerCost: mean(x.plannerCost) }))
      .toSorted((a, b) => byVersion(a.rubric, b.rubric) || a.complexity - b.complexity || a.planner.localeCompare(b.planner)),
    roles: [...roles.values()].map((x) => Object.assign(x, { runs: x.runs.size })).toSorted((a, b) => b.cost - a.cost),
    runCosts: Object.fromEntries(runCosts),
    runTimes,
    bandTimes,
    stepTimes: [...stepTimes.values()].map((x) => ({ step: x.step, runs: x.runs, elapsedMs: mean(x.elapsed), traced: x.traced, agentMs: mean(x.agent) })),
    overlaps: { groups: overlap.groups, excluded: [...overlap.excluded] },
    mainPerRequest,
  }
}

// ---------- render ----------
const n = (x, digits = 1) => (x == null ? '–' : Number.isInteger(x) ? String(x) : x.toFixed(digits))
const usd = (x) => (x == null ? '–' : `$${x.toFixed(2)}`)
const k = (x) => (x >= 1000 ? `${Math.round(x / 1000)}k` : String(x))
const extras = (c) => (c.outputUnknown ? ` + ${c.outputUnknown} req output unknown` : '') + (c.unpriced ? ` + ${c.unpriced} req unpriced` : '')
const runCost = (c) => (c ? usd(c.cost) + extras(c) : '–')
const dur = fmtDuration
const ver = (v) => (v == null ? 'unknown' : `v${v}`)
const rubricCell = (r) =>
  r.rubric == null && r.estimateRubric == null
    ? '–'
    : r.estimateRubric == null || r.estimateRubric === r.rubric
      ? ver(r.rubric)
      : `${ver(r.rubric)} (estimate ${ver(r.estimateRubric)})`
const table = (head, rows) => [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.join(' | ')} |`)].join('\n')

/** The report as markdown. */
export function render(runs, agg, prices = PRICES) {
  const gapCell = (r) => (r.estimate != null && complexityOf(r) != null ? n(complexityOf(r) - r.estimate) : '–')
  return [
    `# Calibration report`,
    ``,
    `${agg.runs} change playbook runs: ${agg.scored} scored, ${agg.traced} traced. Costs are Copilot AI credits as USD (1 credit = $0.01) and, for Claude Code requests, notional list prices (${prices.source}).`,
    ``,
    `## Runs`,
    ``,
    table(
      ['run', 'tier', 'estimate', 'complexity', 'gap', 'overall', 'rubric', 'serious', 'minor', 'follow-ups', 'cost', 'agent time', 'human wait', 'elapsed', 'trace'],
      runs.map((r) => [
        r.id,
        r.tier ?? '–',
        n(r.estimate),
        n(complexityOf(r)),
        gapCell(r),
        r.overall == null ? '–' : `${r.overall}${r.overallFrom === 'judge' ? ' (draft)' : r.overallFrom === 'accepted' ? ' (judge)' : ''}`,
        rubricCell(r),
        r.findings.serious,
        r.findings.minor,
        r.findings.followUps ?? '?',
        runCost(agg.runCosts[r.id]),
        dur(agg.runTimes[r.id]?.agentMs),
        dur(agg.runTimes[r.id]?.humanWaitMs),
        dur(agg.runTimes[r.id]?.elapsedMs),
        (r.traced ?? `none: ${r.untraced}`) + (agg.overlaps.excluded.includes(r.id) ? ', overlaps (left out of totals)' : ''),
      ]),
    ),
    ``,
    `## Complexity: estimate vs judged`,
    ``,
    agg.gap.byRubric.length || agg.gap.mixed
      ? [
          `Gap is judged minus estimate; positive = underestimated. One row per rubric version, over the runs whose estimate and judged complexity used it.`,
          ``,
          ...(agg.gap.byRubric.length
            ? [
                table(
                  ['rubric', 'runs', 'mean gap', 'distribution', 'by tier'],
                  agg.gap.byRubric.map((x) => [
                    ver(x.rubric),
                    x.runs,
                    n(x.mean, 2),
                    x.distribution.map(([g, c]) => `${g > 0 ? '+' : ''}${g}: ${c}`).join(', '),
                    Object.entries(x.byTier)
                      .map(([t, y]) => `${t} ${n(y.mean, 2)} over ${y.runs}`)
                      .join('; '),
                  ]),
                ),
                ``,
              ]
            : []),
          `Mixed versions: ${agg.gap.mixed} ${agg.gap.mixed === 1 ? 'run' : 'runs'} whose estimate and judged complexity used different rubric versions, counted in neither.`,
        ].join('\n')
      : 'No run has both an estimate and a judged complexity yet.',
    ``,
    `## Score by complexity`,
    ``,
    agg.bands.length
      ? table(
          ['rubric', 'complexity', 'runs', 'mean overall', 'serious findings'],
          agg.bands.map((x) => [ver(x.rubric), x.complexity, x.runs, n(x.overall, 2), x.serious]),
        )
      : 'No scored run has a complexity yet.',
    ``,
    `## Score by coder`,
    ``,
    agg.coders.length
      ? table(
          ['rubric', 'complexity', 'coder (model/effort)', 'runs', 'mean overall', 'serious findings', 'exploration'],
          agg.coders.map((x) => [ver(x.rubric), x.complexity, x.coder, x.runs, n(x.overall, 2), x.serious, x.exploration]),
        )
      : 'No scored run has a complexity yet.',
    ``,
    `A run's coder is the model and effort with the most requests among its workflow coder agents (coder and implement roles), or among its \`coder:\` subagents when it has none; "no coder agent" runs were coded by the main thread or by subagents without a role prefix. exploration counts runs marked by the coder exploration quota (\`exploration.coder\` metadata, also on each run in --json).`,
    ``,
    `## Score by planner`,
    ``,
    agg.planners.length
      ? table(
          ['rubric', 'complexity', 'planner (model/effort)', 'runs', 'mean overall', 'serious findings', 'planner cost/run', 'exploration'],
          agg.planners.map((x) => [ver(x.rubric), x.complexity, x.planner, x.runs, n(x.overall, 2), x.serious, usd(x.plannerCost), x.exploration]),
        )
      : 'No scored run has a complexity yet.',
    ``,
    `A run's planner is the model and effort with the most requests among its workflow planner agents (planner, critic and triage roles), or among its \`planner:\` subagents, such as the controller's pre-step planner, when it has none; "no planner agent" runs had neither. planner cost/run is the mean cost of all its planner agents, the pre-step subagent included, over the row's traced runs (priced requests only, as in the role table). exploration counts runs marked by the planner effort exploration (\`exploration.planner\` metadata, AGENTS.md; also on each run in --json); Score by coder counts \`exploration.coder\`.`,
    ``,
    `## Cost and time by complexity`,
    ``,
    agg.bandTimes.length
      ? table(
          ['rubric', 'complexity', 'runs', 'traced', 'mean cost (usd)', 'mean agent time', 'mean human wait', 'mean elapsed'],
          agg.bandTimes.map((x) => [ver(x.rubric), x.complexity, x.runs, x.traced, usd(x.cost), dur(x.agentMs), dur(x.humanWaitMs), dur(x.elapsedMs)]),
        )
      : 'No run has a complexity yet.',
    ``,
    `Bands are per rubric version (a run counts under its judged score's version): each version's complexity anchors differ, so bands of different versions are not directly comparable.`,
    ``,
    `## Time by step`,
    ``,
    agg.stepTimes.length
      ? table(
          ['step', 'runs', 'mean elapsed', 'traced', 'mean agent time'],
          agg.stepTimes.map((x) => [x.step, x.runs, dur(x.elapsedMs), x.traced, dur(x.agentMs)]),
        )
      : 'No closed steps.',
    ``,
    `## Cost and time by role, model and effort`,
    ``,
    agg.roles.length
      ? table(
          ['role', 'model', 'effort', 'runs', 'requests', 'cost', 'agent time'],
          agg.roles.map((x) => [
            x.role,
            x.model,
            x.effort,
            x.runs,
            x.requests,
            usd(x.cost) + extras(x),
            dur(x.activeMs),
          ]),
        )
      : 'No traced runs.',
    ``,
    `Roles come from agent labels: the main thread, workflow roles, and a subagent description's role prefix (${ROLE_PREFIXES.map((r) => `\`${r}:\``).join(', ')}), else a description naming review; "other" is a subagent with neither. A Copilot request with no logged credits (a trace stored by an older version), or a Claude Code request whose model the price table lacks, is unpriced, so its cost is low; so is a Claude Code request whose output its transcript did not record (most subagent and workflow requests), counted as output unknown. ${prices.note}`,
    ``,
    `Agent time is the primary time figure: each agent's busy time per step, its model requests and the tools they ran, summed (parallel agents add up, like cost; time an agent sat idle between turns, waited on a person or on another agent is left out). A Copilot request's start is its record's time less its duration, a Claude Code request's its api-request entry; traces stored before version 4 hold each agent's first request to the end of its last (or, before end times were recorded, its last request's start), which includes such waits. Elapsed (a step: its claim or the previous step's close, whichever is earlier, to its close; a run: created to last close) includes idle gaps and is context only. Human wait (human gates, armed to resolved) is counted apart from both.`,
    ...(agg.overlaps.groups.length
      ? [
          ``,
          `Overlapping runs (same session, overlapping windows, so they claim the same requests): ${agg.overlaps.groups.map((g) => `${g.runs.join(' + ')} (totals use ${g.kept}${g.doubleCounted ? '; windows only partly overlap, so the shared requests are counted twice' : ''})`).join('; ')}. Their per-run costs above include the shared requests.`,
        ]
      : []),
    ``,
    `## Main-thread context per request`,
    ``,
    agg.mainPerRequest.length
      ? table(['run', 'main requests', 'tokens read per request'], agg.mainPerRequest.map((x) => [x.id, x.requests, k(x.perRequest)]))
      : 'No traced main thread.',
  ].join('\n')
}

// ---------- CLI ----------
function main(argv) {
  const opt = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined)
  const root = opt('--root')
  const dirs = logDirs(opt)
  const bd = bdRunner(root)
  const issues = bd(['list', '--all', '-n', '0'])
  // A run without a review step has no follow-ups; any other failure leaves the count unknown, not zero.
  const followUpsOf = (step) => {
    try {
      return (bd(['show', step]).dependents ?? []).filter((d) => d.type === 'discovered-from').map((d) => d.id)
    } catch (e) {
      if (/not_found|not found/i.test(`${e.stderr ?? ''}${e.message}`)) return []
      process.stderr.write(`calibrate: follow-ups of ${step} unknown: ${(e.stderr?.toString().trim() || e.message).split('\n')[0]}\n`)
      return null
    }
  }
  const traceOf = (id) => {
    try {
      const work = trace(readRecord(id, bd), dirs)
      const why = untracedWhy(work)
      return why ? { work: null, why } : { work, why: null }
    } catch (e) {
      return { work: null, why: e.message.split('\n')[0] }
    }
  }
  const runs = joinRuns(issues, { followUpsOf, traceOf })
  const agg = aggregate(runs)
  process.stdout.write(`${argv.includes('--json') ? JSON.stringify({ runs, aggregate: agg }, null, 2) : render(runs, agg)}\n`)
  // Only finished runs: a backfill of an open run misses its remaining work and would stand in for it as 'stored'.
  if (argv.includes('--write'))
    for (const { id, work } of runs.filter((r) => r.traced === 'backfilled'))
      execFileSync('bd', [...(root ? ['-C', root] : []), 'update', id, '--set-metadata', `work=${JSON.stringify(work)}`], { stdio: ['ignore', 'ignore', 'pipe'] })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2))
  } catch (e) {
    process.stderr.write(`calibrate: ${(e.stderr?.toString().trim() || e.message).split('\n')[0]}\n`)
    process.exitCode = 1
  }
}
