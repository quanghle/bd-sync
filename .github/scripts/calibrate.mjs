#!/usr/bin/env node
// The evidence for changing how complexity is judged and which model and effort each role gets: every change playbook
// run's complexity estimate and judged complexity, its score, the findings its review filed, and who did the work with
// which model and effort at what cost (Copilot AI credits, as USD) and for how long: agent active time (first request to the end of the last,
// per agent and step) next to cost, each step's elapsed time, and the human wait at gates (armed to resolved), apart.
//
//   node .github/scripts/calibrate.mjs [--root <checkout>] [--sessions <dir>] [--json] [--write]
//
// Read-only unless --write, which stores a backfilled trace as the work metadata of a run that has none. Traces come from
// the run's work metadata, else from trace-run on this machine's session logs. Costs are the AI credits Copilot logged per
// request (1 credit = $0.01); a stored trace without them is unpriced. Timing
// (step elapsed times, gate waits) is read from the bd list at report time, not from the stored trace, which is written
// before the run's last steps and its score gate close.
import { execFileSync } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { activeMs, bdRunner, fmtDuration, readRecord, stepFrom, timingOf, trace } from './trace-run.mjs'

// ---------- roles ----------
// What an agent did, from its trace label: 'main', a workflow's '<workflow>:<role>[:...]', or a subagent's
// '<type>: <description>'. A heuristic over labels the callers chose, so 'other' is a real answer.
const WORKFLOW_ROLES = [
  [/^(coder|implement)\b/, 'coder'],
  [/^review\b/, 'reviewer'],
  [/^validate\b/, 'validator'],
  [/^planner\b|^critic\b|^triage\b/, 'planner'],
  [/^(gate|record|heartbeat|claim|setup|bd|trace)\b/, 'mechanical'],
  [/^judge\b/, 'judge'],
]
export function roleOf(agent) {
  if (agent.kind === 'main') return 'main'
  if (agent.kind === 'workflow') {
    const role = agent.label.split(':')[1] ?? ''
    return WORKFLOW_ROLES.find(([re]) => re.test(role))?.[1] ?? 'other'
  }
  return /review/i.test(agent.label) ? 'reviewer' : 'other'
}

// ---------- cost ----------
const USD_PER_CREDIT = 0.01
const NANO = 1e9

/** USD for a token count from the AI credits it cost (nano_aiu); null when the trace recorded none (an older trace). */
export const costOf = (tokens) => (typeof tokens?.nano_aiu === 'number' ? (tokens.nano_aiu / NANO) * USD_PER_CREDIT : null)

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
export function aggregate(runs) {
  const overlap = overlaps(runs)
  const withGap = runs.filter((r) => r.estimate != null && complexityOf(r) != null)
  const gaps = withGap.map((r) => complexityOf(r) - r.estimate)
  const gapBy = (key) =>
    Object.fromEntries(
      [...new Set(withGap.map(key))].map((k) => {
        const g = withGap.filter((r) => key(r) === k).map((r) => complexityOf(r) - r.estimate)
        return [k, { runs: g.length, mean: mean(g) }]
      }),
    )
  const bands = {}
  for (const r of runs.filter((x) => complexityOf(x) != null && x.overall != null)) {
    const b = (bands[complexityOf(r)] ??= { runs: 0, overall: [], serious: 0 })
    b.runs++
    b.overall.push(r.overall)
    b.serious += r.findings.serious
  }
  const roles = new Map()
  const runCosts = new Map()
  for (const r of runs)
    for (const a of agentsOf(r)) {
      const c = costOf(a.tokens)
      const rc = runCosts.get(r.id) ?? { cost: 0, unpriced: 0 }
      if (c == null) rc.unpriced += a.requests
      else rc.cost += c
      runCosts.set(r.id, rc)
      // An overlapping run's requests are already in the run kept for its group.
      if (overlap.excluded.has(r.id)) continue
      const key = `${roleOf(a)}\0${a.model}\0${a.effort}`
      const x = roles.get(key) ?? { role: roleOf(a), model: a.model, effort: a.effort, runs: new Set(), requests: 0, cost: 0, activeMs: 0, unpriced: 0 }
      x.runs.add(r.id)
      x.requests += a.requests
      x.activeMs += activeMs(a)
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
  const bandTimes = {}
  for (const k of new Set(runs.map(complexityOf).filter((c) => c != null))) {
    const rs = runs.filter((r) => complexityOf(r) === k)
    const tracedRuns = rs.filter((r) => r.work)
    bandTimes[k] = {
      runs: rs.length,
      traced: tracedRuns.length,
      cost: mean(tracedRuns.map((r) => runCosts.get(r.id)?.cost ?? 0)),
      agentMs: mean(tracedRuns.map((r) => runTimes[r.id].agentMs)),
      humanWaitMs: meanOf(rs.map((r) => runTimes[r.id].humanWaitMs)),
      elapsedMs: meanOf(rs.map((r) => runTimes[r.id].elapsedMs)),
    }
  }
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
    gap: {
      runs: gaps.length,
      mean: mean(gaps),
      distribution: [...new Set(gaps)].toSorted((a, b) => a - b).map((g) => [g, gaps.filter((x) => x === g).length]),
      byTier: gapBy((r) => r.tier),
    },
    bands: Object.fromEntries(Object.entries(bands).map(([k, b]) => [k, { runs: b.runs, overall: mean(b.overall), serious: b.serious }])),
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
const runCost = (c) => (c ? usd(c.cost) + (c.unpriced ? ` + ${c.unpriced} req unpriced` : '') : '–')
const dur = fmtDuration
const table = (head, rows) => [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.join(' | ')} |`)].join('\n')

/** The report as markdown. */
export function render(runs, agg) {
  const gapCell = (r) => (r.estimate != null && complexityOf(r) != null ? n(complexityOf(r) - r.estimate) : '–')
  return [
    `# Calibration report`,
    ``,
    `${agg.runs} change playbook runs: ${agg.scored} scored, ${agg.traced} traced. Costs are Copilot AI credits as USD (1 credit = $0.01).`,
    ``,
    `## Runs`,
    ``,
    table(
      ['run', 'tier', 'estimate', 'complexity', 'gap', 'overall', 'serious', 'minor', 'follow-ups', 'cost', 'agent time', 'human wait', 'elapsed', 'trace'],
      runs.map((r) => [
        r.id,
        r.tier ?? '–',
        n(r.estimate),
        n(complexityOf(r)),
        gapCell(r),
        r.overall == null ? '–' : `${r.overall}${r.overallFrom === 'judge' ? ' (draft)' : r.overallFrom === 'accepted' ? ' (judge)' : ''}`,
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
    agg.gap.runs
      ? [
          `${agg.gap.runs} runs with both; mean gap ${n(agg.gap.mean, 2)} (judged minus estimate; positive = underestimated).`,
          `Distribution: ${agg.gap.distribution.map(([g, c]) => `${g > 0 ? '+' : ''}${g}: ${c}`).join(', ')}.`,
          `By tier: ${Object.entries(agg.gap.byTier).map(([t, x]) => `${t} ${n(x.mean, 2)} over ${x.runs}`).join('; ')}.`,
        ].join('\n')
      : 'No run has both an estimate and a judged complexity yet.',
    ``,
    `## Score by complexity`,
    ``,
    Object.keys(agg.bands).length
      ? table(['complexity', 'runs', 'mean overall', 'serious findings'], Object.entries(agg.bands).map(([b, x]) => [b, x.runs, n(x.overall, 2), x.serious]))
      : 'No scored run has a complexity yet.',
    ``,
    `## Cost and time by complexity`,
    ``,
    Object.keys(agg.bandTimes).length
      ? table(
          ['complexity', 'runs', 'traced', 'mean cost (usd)', 'mean agent time', 'mean human wait', 'mean elapsed'],
          Object.entries(agg.bandTimes).map(([b, x]) => [b, x.runs, x.traced, usd(x.cost), dur(x.agentMs), dur(x.humanWaitMs), dur(x.elapsedMs)]),
        )
      : 'No run has a complexity yet.',
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
            usd(x.cost) + (x.unpriced ? ` + ${x.unpriced} req unpriced` : ''),
            dur(x.activeMs),
          ]),
        )
      : 'No traced runs.',
    ``,
    `Roles come from agent labels (main thread, workflow roles, subagent descriptions); "other" is a subagent whose description names no role. A request with no logged credits (a trace stored by an older version) is unpriced, so its cost is low.`,
    ``,
    `Agent time is the primary time figure: each agent's span from its first request to the end of its last, per step, summed (parallel agents add up, like cost; a main thread's span includes time it waited on its own agents or on a person). A request's start is its record's time less its duration; traces stored before end times were recorded stop at the last request's start. Elapsed (a step: its claim or the previous step's close, whichever is earlier, to its close; a run: created to last close) includes idle gaps and is context only. Human wait (human gates, armed to resolved) is counted apart from both.`,
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
  const sessionsDir = opt('--sessions') ?? join(process.env.COPILOT_HOME ?? join(homedir(), '.copilot'), 'session-state')
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
      const work = trace(readRecord(id, bd), { sessionsDir })
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
