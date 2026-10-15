#!/usr/bin/env node
// Which agents did each step of a bd playbook run, with which model and effort, from Copilot CLI session logs.
//
//   node .github/scripts/trace-run.mjs <run> [--root <checkout>] [--sessions <dir>] [--actor <name>] [--write] [--summary]
//
// Every agent actor in the run's bd history (<name>/copilot-<8 hex>, or a BD_SESSION sub-actor's <name>/copilot-<8 hex>.<name>)
// is a Copilot CLI session whose id ends with those 8 hex digits. Its events.jsonl holds the session's own thread, its
// subagents and its workflow agents; every model request in it goes to the first step of the run closed at or after it.
// Requests before the run was created or after its last closed step are left out; an issue without steps is its own only
// step. Only labels (an agent's display name or workflow label, at most 80 characters), model ids, effort, token counts,
// AI credits and times are read out: prompts, tool output and reasoning never reach the result, which --write stores as
// the run's work metadata.
// It also records times: each agent's active span per step (its first request's start to the end of its last), each step's
// elapsed time (from its claim or the previous step's close, whichever is earlier, to its close), gate waits (armed to
// resolved) and the human wait at human gates.
// It prints the result as JSON, or with --summary as a short list of who did what for a comment.
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SESSION_SUFFIX = /\/copilot-([0-9a-f]{8})(?:\.[0-9a-z-]+)*$/
const LABEL_MAX = 80
const WORKFLOW_NOTE = /Workflow "([^"]+)" run ([0-9a-f-]{36})/

const label = (s) => (s.length > LABEL_MAX ? `${s.slice(0, LABEL_MAX - 1)}…` : s)
export const readJson = (file) => {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}
export const readJsonl = (file, keep = () => true) =>
  readFileSync(file, 'utf8')
    .split('\n')
    .flatMap((line) => {
      if (!line || !keep(line)) return []
      try {
        return [JSON.parse(line)]
      } catch {
        return []
      }
    })
const list = (dir) => (existsSync(dir) ? readdirSync(dir) : [])

/** The 8 hex digits of an agent actor's session, or null for a person or any other actor. */
export const sessionSuffix = (actor) => SESSION_SUFFIX.exec(actor)?.[1] ?? null

/** Sessions under sessionsDir whose id ends with the suffix and that have an event log. */
export function findSessions(sessionsDir, suffix) {
  return list(sessionsDir)
    .filter((d) => d.endsWith(suffix) && existsSync(join(sessionsDir, d, 'events.jsonl')))
    .map((session) => ({ dir: sessionsDir, session }))
}

const EVENT_TYPES = ['"type":"session.usage_record"', '"type":"subagent.started"', '"type":"subagent.configured"', 'system.notification']

/**
 * The subagents a session started, from its events: { agents: Map agentId -> { agentName, agentDisplayName (a workflow
 * agent's label), workflowRunId, model, effort }, workflows: Map workflow run id -> workflow name (from its completion
 * notice) }.
 */
export function subagentsOf(events) {
  const agents = new Map()
  const workflows = new Map()
  for (const e of events) {
    if (e.type === 'system.notification') {
      const m = WORKFLOW_NOTE.exec(e.data?.content ?? '')
      if (m) workflows.set(m[2], m[1])
    } else if (e.type === 'subagent.started' && e.agentId) {
      agents.set(e.agentId, { ...agents.get(e.agentId), ...e.data })
    } else if (e.type === 'subagent.configured' && e.agentId) {
      agents.set(e.agentId, { ...agents.get(e.agentId), effort: e.data?.reasoningEffort })
    }
  }
  return { agents, workflows }
}

/**
 * A session's model requests, one per API call (usage record), with the agent that made it. Each: id, model, effort,
 * tokens (input without its cache parts, output, cache_read, cache_write, nano_aiu: the AI credits it cost, in
 * billionths), ts (its start: the record's time less its duration), end (the record's time), owned (the log is the
 * session that made it; a fork or resume copies its parent's records), and the agent's kind and label: 'main', or a
 * subagent's, or a workflow agent's ('<workflow>:<label>', the workflow from its completion notice, else 'workflow').
 */
export function requestsOf(events, session = null) {
  const { agents, workflows } = subagentsOf(events)
  const labelOf = (id) => {
    const a = agents.get(id)
    if (!a) return { kind: 'subagent', label: label(id) }
    const name = a.agentDisplayName ?? a.agentDescription ?? a.agentName ?? id
    if (a.workflowRunId) return { kind: 'workflow', label: label(`${workflows.get(a.workflowRunId) ?? 'workflow'}:${name}`) }
    return { kind: 'subagent', label: label([a.agentName, name].filter((x, i, all) => x && all.indexOf(x) === i).join(': ')) }
  }
  const out = []
  for (const e of events) {
    const u = e.type === 'session.usage_record' ? e.data?.usage : null
    if (!u?.model || !e.timestamp) continue
    const end = Date.parse(e.timestamp)
    if (!Number.isFinite(end)) continue
    const cache_read = u.cacheReadTokens ?? 0
    const cache_write = u.cacheWriteTokens ?? 0
    const who = e.agentId ? labelOf(e.agentId) : { kind: 'main', label: 'main' }
    out.push({
      id: u.apiCallId ?? u.accounting?.usageId ?? e.id,
      ts: new Date(end - (u.duration ?? 0)).toISOString(),
      end: e.timestamp,
      model: u.model,
      effort: u.reasoningEffort ?? agents.get(e.agentId)?.effort ?? 'unknown',
      tokens: { input: Math.max(0, (u.inputTokens ?? 0) - cache_read - cache_write), output: u.outputTokens ?? 0, cache_read, cache_write, nano_aiu: u.copilotUsage?.totalNanoAiu ?? 0 },
      owned: !session || !u.accounting?.sourceSessionId || u.accounting.sourceSessionId === session,
      ...who,
    })
  }
  return out
}

/** The events of a session's log that requests and subagents are read from (the log can be tens of MB: other lines are skipped unparsed). */
export const sessionEvents = (dir, session) => readJsonl(join(dir, session, 'events.jsonl'), (line) => EVENT_TYPES.some((t) => line.includes(t)))

/** The requests in a session's event log. */
export const sessionRequests = (dir, session) => requestsOf(sessionEvents(dir, session), session)

const ZERO = () => ({ input: 0, output: 0, cache_read: 0, cache_write: 0, nano_aiu: 0 })
const add = (t, r) => {
  for (const k of Object.keys(t)) t[k] += r.tokens[k] ?? 0
}

const pad2 = (n) => String(n).padStart(2, '0')
const msAt = (t) => (t ? Date.parse(t) : NaN)

/**
 * An agent's active time in ms: its first request to the end of its last (active_ms when the trace recorded it; a v1
 * trace without end times stops at the last request's start). 0 when its times are missing, never negative.
 */
export const activeMs = (a) => {
  if (typeof a?.active_ms === 'number') return a.active_ms
  const ms = Date.parse(a?.end ?? a?.last) - Date.parse(a?.first)
  return Number.isFinite(ms) ? Math.max(0, ms) : 0
}

/** A duration in ms as '42s', '12m 05s' or '2h 03m'; '–' when there is none. */
export const fmtDuration = (ms) => {
  if (ms == null || !Number.isFinite(ms)) return '–'
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${pad2(s % 60)}s`
  const m = Math.floor(s / 60)
  return `${Math.floor(m / 60)}h ${pad2(m % 60)}m`
}

/**
 * A run's times from its steps (record shape, as readRecord gives it): each closed non-gate step's elapsed time, from the
 * earlier of its claim and the previous step's close (in close order, gates included; the run's creation for the first)
 * to its close; each gate's wait, armed to resolved (null unless both are known); the human wait, summed over resolved
 * human gates; and the run's elapsed time, created to its last close (null while nothing is closed).
 */
export function timingOf({ createdAt, steps }) {
  const at = msAt
  const ok = Number.isFinite
  const closed = steps.filter((s) => s.closedAt).toSorted((a, b) => at(a.closedAt) - at(b.closedAt))
  const out = []
  closed.forEach((s, i) => {
    if (s.type === 'gate') return
    const close = at(s.closedAt)
    const prev = i ? { t: closed[i - 1].closedAt, from: 'previous close' } : { t: createdAt ?? null, from: 'created' }
    const claim = s.startedAt && at(s.startedAt) <= close ? { t: s.startedAt, from: 'claim' } : null
    const start = [prev, claim].filter((c) => c && ok(at(c.t))).reduce((a, c) => (!a || at(c.t) < at(a.t) ? c : a), null)
    out.push({ step: s.id, start: start?.t ?? null, start_from: start?.from ?? null, closed_at: s.closedAt, elapsed_ms: start ? close - at(start.t) : null })
  })
  const gates = steps
    .filter((s) => s.type === 'gate')
    .map((s) => {
      const armed = s.gate?.armedAt ?? null
      const wait = at(s.closedAt) - at(armed)
      return { gate: s.id, type: s.gate?.type ?? null, armed_at: armed, resolved_at: s.closedAt ?? null, wait_ms: ok(wait) ? wait : null }
    })
  const last = closed.length ? Math.max(...closed.map((s) => at(s.closedAt))) : NaN
  const elapsed = last - at(createdAt)
  return {
    elapsed_ms: ok(elapsed) ? elapsed : null,
    human_wait_ms: gates.filter((g) => g.type === 'human' && g.wait_ms != null).reduce((n, g) => n + g.wait_ms, 0),
    steps: out,
    gates,
  }
}

/**
 * The trace of a run from its bd record and the session logs under sessionsDir.
 * record: { run, createdAt, steps: [{ id, closedAt | null, startedAt?, type?, gate?: { type, armedAt } }], actors: [string] }
 */
export function trace(record, { sessionsDir, now = new Date() }) {
  const closed = record.steps.filter((s) => s.closedAt).sort((a, b) => a.closedAt.localeCompare(b.closedAt))
  const sessions = []
  const missing = []
  const seenSessions = new Set()
  // A resumed or forked session starts with a copy of its parent's records (same API call ids): count each request once,
  // for the session that made it (owned), else the first one read.
  const byId = new Map()
  for (const actor of new Set(record.actors)) {
    const suffix = sessionSuffix(actor)
    if (!suffix) continue
    const found = findSessions(sessionsDir, suffix)
    if (!found.length && !missing.some((m) => sessionSuffix(m) === suffix)) missing.push(actor)
    for (const { dir, session } of found) {
      if (seenSessions.has(session)) continue
      seenSessions.add(session)
      sessions.push({ actor, session })
      for (const r of sessionRequests(dir, session)) {
        const prev = byId.get(r.id)
        if (!prev || (r.owned && !prev.owned)) byId.set(r.id, { ...r, actor })
      }
    }
  }
  const requests = [...byId.values()].sort((a, b) => a.ts.localeCompare(b.ts))

  const steps = new Map(closed.map((s) => [s.id, { step: s.id, closed_at: s.closedAt, agents: new Map() }]))
  const totals = new Map()
  let outside = 0
  for (const r of requests) {
    const step = r.ts >= record.createdAt ? closed.find((s) => s.closedAt >= r.ts) : undefined
    if (!step) {
      outside++
      continue
    }
    const key = [r.actor, r.kind, r.label, r.model, r.effort].join('\0')
    const agents = steps.get(step.id).agents
    const end = r.end ?? r.ts
    const a = agents.get(key) ?? { actor: r.actor, kind: r.kind, label: r.label, model: r.model, effort: r.effort, requests: 0, tokens: ZERO(), first: r.ts, last: r.ts, end }
    a.requests++
    add(a.tokens, r)
    if (r.ts < a.first) a.first = r.ts
    if (r.ts > a.last) a.last = r.ts
    if (end > a.end) a.end = end
    agents.set(key, a)
    const tk = `${r.model}\0${r.effort}`
    const t = totals.get(tk) ?? { model: r.model, effort: r.effort, requests: 0, active_ms: 0, tokens: ZERO() }
    t.requests++
    add(t.tokens, r)
    totals.set(tk, t)
  }
  for (const s of steps.values())
    for (const a of s.agents.values()) {
      a.active_ms = activeMs({ first: a.first, end: a.end })
      totals.get(`${a.model}\0${a.effort}`).active_ms += a.active_ms
    }

  return {
    version: 3,
    traced_at: now.toISOString(),
    run: record.run,
    sessions,
    missing,
    open_steps: record.steps.filter((s) => !s.closedAt).map((s) => s.id),
    steps: [...steps.values()]
      .filter((s) => s.agents.size)
      .map((s) => ({ ...s, agents: [...s.agents.values()].sort((a, b) => a.first.localeCompare(b.first)) })),
    totals: [...totals.values()].sort((a, b) => b.requests - a.requests),
    outside_requests: outside,
    timing: timingOf(record),
  }
}

const short = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${Math.round(n / 1e3)}k` : String(n))
const fmtTokens = (t) =>
  `in ${short(t.input + t.cache_read + t.cache_write)} (cache read ${short(t.cache_read)}), out ${short(t.output)}, ${(t.nano_aiu / 1e9).toFixed(1)} credits`

/**
 * The trace as a few lines for a comment: the times, then per step its elapsed time and each agent's model, effort,
 * requests and active time; then totals.
 */
export function summarize(t) {
  const step = (id) => (id.startsWith(`${t.run}.`) ? id.slice(t.run.length + 1) : id)
  const agentMs = t.steps.reduce((n, s) => n + s.agents.reduce((m, a) => m + activeMs(a), 0), 0)
  const elapsed = (id) => fmtDuration(t.timing?.steps.find((x) => x.step === id)?.elapsed_ms)
  return [
    `Work trace: ${t.sessions.length} session(s)` +
      (t.missing.length ? `; not on this machine: ${t.missing.join(', ')}` : '') +
      (t.open_steps.length ? `; open steps not traced: ${t.open_steps.map(step).join(', ')}` : ''),
    `Time: agents ${fmtDuration(agentMs)} (first to last request per agent and step, summed; approximate), ` +
      `human wait ${fmtDuration(t.timing?.human_wait_ms)}, elapsed ${fmtDuration(t.timing?.elapsed_ms)} (created to last close; includes idle gaps)`,
    ...t.steps.map(
      (s) => `- ${step(s.step)} (elapsed ${elapsed(s.step)}): ${s.agents.map((a) => `${a.label} (${a.model}, ${a.effort}, ${a.requests} req, ${fmtDuration(activeMs(a))})`).join('; ')}`,
    ),
    ...(t.totals.length
      ? ['Totals:', ...t.totals.map((x) => `- ${x.model}, ${x.effort}: ${x.requests} req, ${fmtDuration(x.active_ms)}, ${fmtTokens(x.tokens)}`)]
      : ['No model requests found.']),
  ].join('\n')
}

// ---------- bd ----------
const RUN_ID = /^[a-z0-9]+-[a-z0-9]+(\.[a-z0-9-]+)*$/
const asList = (x, key) => (Array.isArray(x) ? x : (x?.[key] ?? []))

/** Runs bd with these arguments and --json in root (or bd's own default), returning the parsed output. */
export const bdRunner = (root) => (args) =>
  JSON.parse(execFileSync('bd', [...(root ? ['-C', root] : []), ...args, '--json'], { encoding: 'utf8', maxBuffer: 64 << 20 }))

/**
 * A step of the record from a bd issue (as bd list or show gives it): its id, close time, claim time, type and, for a
 * gate, the gate's type and when it was armed. Only ids, types and timestamps are read.
 */
export const stepFrom = (c, closedAt = c.status === 'closed' ? (c.closed_at ?? null) : null) => ({
  id: c.id,
  closedAt,
  startedAt: c.started_at ?? null,
  type: c.issue_type ?? null,
  gate: c.issue_type === 'gate' ? { type: c.metadata?.gate?.type ?? null, armedAt: c.metadata?.gate?.armed_at ?? null } : null,
})

/**
 * The run's bd record from bd(args): when it was created, when each step was claimed and closed (and, for gates, armed),
 * and every actor in its history. A step counts as closed only while it is (a reopened one is open again); an issue
 * without steps is its own only step.
 */
export function readRecord(run, bd) {
  if (!RUN_ID.test(run)) throw new Error(`not a bd issue id: ${run}`)
  const history = (id) => asList(bd(['history', id]), 'events')
  const closedAt = (status, h) => (status === 'closed' ? (h.filter((e) => e.op === 'closed').at(-1)?.ts ?? null) : null)
  const own = history(run)
  // Only the run's own steps: bd lists nested children too (findings under a review step), which would split a step.
  const all = asList(bd(['list', '--all', '-n', '0', '--parent', run]), 'issues')
  const direct = all.filter((c) => /^[^.]+$/.test(c.id.slice(run.length + 1)))
  const steps = direct.map((c) => {
    const h = history(c.id)
    own.push(...h)
    return stepFrom(c, closedAt(c.status, h))
  })
  // Nested children aren't steps, but a session that only worked on them (filed or closed a finding) still did the work.
  for (const c of all.filter((c) => !direct.includes(c))) own.push(...history(c.id))
  if (!steps.length) {
    const self = bd(['show', run])
    steps.push(stepFrom({ ...self, id: run }, closedAt(self.status, own)))
  }
  const createdAt = own.find((e) => e.issue_id === run && e.op === 'created')?.ts
  if (!createdAt) throw new Error(`no created event for ${run}`)
  return { run, createdAt, steps, actors: own.map((e) => e.actor).filter(Boolean) }
}

function main(argv) {
  const valued = ['--sessions', '--root', '--actor']
  const opt = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined)
  const run = argv.find((a, i) => !a.startsWith('--') && !valued.includes(argv[i - 1]))
  if (!run) throw new Error('usage: trace-run.mjs <run> [--root <checkout>] [--sessions <dir>] [--actor <name>] [--write] [--summary]')
  const root = opt('--root')
  const sessionsDir = opt('--sessions') ?? join(process.env.COPILOT_HOME ?? join(homedir(), '.copilot'), 'session-state')
  const result = trace(readRecord(run, bdRunner(root)), { sessionsDir })
  // Print first, so a failed write still leaves the trace on stdout.
  process.stdout.write(`${argv.includes('--summary') ? summarize(result) : JSON.stringify(result, null, 2)}\n`)
  if (!argv.includes('--write')) return
  const actor = opt('--actor')
  const args = [...(root ? ['-C', root] : []), 'update', run, '--set-metadata', `work=${JSON.stringify(result)}`, ...(actor ? ['--actor', actor] : [])]
  try {
    execFileSync('bd', args, { stdio: ['ignore', 'ignore', 'pipe'], encoding: 'utf8' })
  } catch (e) {
    process.stderr.write(`could not store the work metadata on ${run}: ${(e.stderr || e.message).trim()}\n`)
    process.exitCode = 1
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2))
  } catch (e) {
    // One line, not a stack: score-issue puts this in a bd comment.
    process.stderr.write(`trace-run: ${(e.stderr?.toString().trim() || e.message).split('\n')[0]}\n`)
    process.exitCode = 1
  }
}
