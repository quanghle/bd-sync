#!/usr/bin/env node
// Which agents did each step of a bd playbook run, with which model and effort, from Copilot CLI session logs and Claude
// Code transcripts.
//
//   node .github/scripts/trace-run.mjs <run> [--root <checkout>] [--sessions <dir>] [--projects <dir>] [--actor <name>] [--write] [--summary]
//
// Every agent actor in the run's bd history is a session of one harness, found by the 8 hex digits its actor ends with:
// <name>/copilot-<8 hex> (or a BD_SESSION sub-actor's <name>/copilot-<8 hex>.<name>) is a Copilot CLI session under
// --sessions (default $COPILOT_HOME/session-state), whose events.jsonl holds its own thread, its subagents and its workflow
// agents; <name>/claude-<8 hex> (or a subagent's <name>/claude-<8 hex>.agent-<id>) is a Claude Code session under --projects
// (default $CLAUDE_CONFIG_DIR/projects), with a transcript for its own thread, each subagent and each workflow agent. Every
// model request goes to the first step of the run closed at or after it. Requests before the run started (a run: its
// creation; an issue without steps, which is its own only step: its first claim) or after its last closed step are left
// out. Only labels (an agent's display name, description or workflow label, at most 80 characters), model ids, effort,
// token counts, Copilot AI credits and times are read out: prompts, tool input and output and reasoning never reach the
// result, which --write stores as the run's work metadata.
// It also records times: each agent's busy time per step (its model requests and the tools they ran, as a union of
// intervals: not the time it sat idle between turns, waited on a person or on another agent, which is traced on its own),
// each step's elapsed time (from its claim or the previous step's close, whichever is earlier, to its close), gate waits
// (armed to resolved) and the human wait at human gates.
// It prints the result as JSON, or with --summary as a short list of who did what for a comment.
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

// A session's sub-actors (BD_SESSION, a subagent's agent-<id>) add dot-separated labels, which keep [A-Za-z0-9_-].
const SESSION_SUFFIX = /\/copilot-([0-9a-f]{8})(?:\.[0-9A-Za-z_-]+)*$/
const CLAUDE_SUFFIX = /\/claude-([0-9a-f]{8})(?:\.[0-9A-Za-z_-]+)*$/
// An agent session of any harness, traced or not (bd names them <user>/<harness>-<8 hex>).
const AGENT_SESSION = /\/([a-z]+)-[0-9a-f]{8}(?:\.[0-9A-Za-z_-]+)*$/
const LABEL_MAX = 80
// Tools whose time is not the calling agent's work: waiting on a person, or on another agent (traced on its own).
const WAITING_TOOLS = new Set(['AskUserQuestion', 'ask_user', 'ExitPlanMode', 'exit_plan_mode', 'Agent', 'Task', 'task', 'read_agent', 'write_agent', 'TaskOutput', 'TaskStop'])
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

/** The 8 hex digits of a Copilot agent actor's session, or null for a person or any other actor. */
export const sessionSuffix = (actor) => SESSION_SUFFIX.exec(actor)?.[1] ?? null

/** The 8 hex digits of a Claude Code agent actor's session, or null for a person or any other actor. */
export const claudeSuffix = (actor) => CLAUDE_SUFFIX.exec(actor)?.[1] ?? null

/** The harness and session suffix of an agent actor, or null for a person or any other actor. */
export const harnessOf = (actor) => {
  const copilot = sessionSuffix(actor)
  if (copilot) return { harness: 'copilot', suffix: copilot }
  const claude = claudeSuffix(actor)
  return claude ? { harness: 'claude', suffix: claude } : null
}

// ---------- busy time ----------
/** The total length in ms of [start, end] intervals (ms), overlaps counted once. */
export function unionMs(spans) {
  let total = 0
  let cur = null
  for (const [a, b] of spans.filter(([a, b]) => Number.isFinite(a) && Number.isFinite(b) && b > a).toSorted((x, y) => x[0] - y[0])) {
    if (cur && a <= cur[1]) cur[1] = Math.max(cur[1], b)
    else {
      if (cur) total += cur[1] - cur[0]
      cur = [a, b]
    }
  }
  return cur ? total + cur[1] - cur[0] : total
}

/** A [start, end] interval less the holes cut out of it, as the intervals left. */
export function minus([a, b], holes) {
  let left = [[a, b]]
  for (const [h0, h1] of holes)
    left = left.flatMap(([x, y]) => (h1 <= x || h0 >= y ? [[x, y]] : [...(h0 > x ? [[x, h0]] : []), ...(h1 < y ? [[h1, y]] : [])]))
  return left
}

/**
 * Attaches each tool span ({ agent, span: [start, end] }) to the request of the same agent (requests' agent key) that
 * started last at or before it, as that request's tools; a span before any request of its agent is dropped.
 */
export function attachTools(requests, tools, agentOf) {
  const byAgent = new Map()
  for (const r of requests) {
    r.tools ??= []
    const k = agentOf(r)
    byAgent.set(k, [...(byAgent.get(k) ?? []), r])
  }
  for (const rs of byAgent.values()) rs.sort((x, y) => msAt(x.ts) - msAt(y.ts))
  for (const t of tools) {
    const rs = byAgent.get(t.agent) ?? []
    let owner = null
    for (const r of rs) {
      if (msAt(r.ts) <= t.span[0]) owner = r
      else break
    }
    owner?.tools.push(t.span)
  }
  return requests
}

/** Sessions under sessionsDir whose id ends with the suffix and that have an event log. */
export function findSessions(sessionsDir, suffix) {
  return list(sessionsDir)
    .filter((d) => d.endsWith(suffix) && existsSync(join(sessionsDir, d, 'events.jsonl')))
    .map((session) => ({ dir: sessionsDir, session }))
}

const EVENT_TYPES = [
  '"type":"session.usage_record"',
  '"type":"subagent.started"',
  '"type":"subagent.configured"',
  'system.notification',
  '"type":"tool.execution_start"',
  '"type":"tool.execution_complete"',
  '"type":"permission.requested"',
  '"type":"permission.completed"',
]

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
 * The busy spans of the tools a Copilot session's agents ran, from its events: { agent (its agentId, '' for the main
 * thread), span: [start, end] in ms }, execution start to completion less any permission prompt in between; a tool that
 * waits on a person or another agent (WAITING_TOOLS) or started a subagent is left out, as is one that never completed.
 */
export function copilotTools(events) {
  const started = new Map()
  const prompts = new Map()
  const subagentCalls = new Set(events.filter((e) => e.type === 'subagent.started').map((e) => e.data?.toolCallId).filter(Boolean))
  const out = []
  for (const e of events) {
    const t = msAt(e.timestamp)
    if (e.type === 'permission.requested') {
      const id = e.data?.permissionRequest?.toolCallId
      if (id) prompts.set(id, [...(prompts.get(id) ?? []), [t, Infinity]])
    } else if (e.type === 'permission.completed') {
      const open = (prompts.get(e.data?.toolCallId) ?? []).find((p) => p[1] === Infinity)
      if (open) open[1] = t
    }
  }
  for (const e of events) {
    const t = msAt(e.timestamp)
    if (e.type === 'tool.execution_start' && e.data?.toolCallId) started.set(e.data.toolCallId, { t, name: e.data.toolName, agent: e.agentId ?? '' })
    else if (e.type === 'tool.execution_complete') {
      const s = started.get(e.data?.toolCallId)
      if (!s) continue
      started.delete(e.data.toolCallId)
      if (WAITING_TOOLS.has(s.name) || subagentCalls.has(e.data.toolCallId)) continue
      for (const span of minus([s.t, t], prompts.get(e.data.toolCallId) ?? [])) out.push({ agent: s.agent, span })
    }
  }
  return out
}

/**
 * A session's model requests, one per API call (usage record), with the agent that made it. Each: id, harness
 * ('copilot'), model, effort, tokens (input without its cache parts, output, cache_read, cache_write, nano_aiu: the AI
 * credits it cost, in billionths), ts (its start: the record's time less its duration), end (the record's time), tools
 * (the busy spans of the tools it ran, copilotTools), owned (the log is the session that made it; a fork or resume
 * copies its parent's records), and the agent's kind and label: 'main', or a subagent's, or a workflow agent's
 * ('<workflow>:<label>', the workflow from its completion notice, else 'workflow').
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
      harness: 'copilot',
      agentId: e.agentId ?? '',
      ts: new Date(end - (u.duration ?? 0)).toISOString(),
      end: e.timestamp,
      model: u.model,
      effort: u.reasoningEffort ?? agents.get(e.agentId)?.effort ?? 'unknown',
      tokens: { input: Math.max(0, (u.inputTokens ?? 0) - cache_read - cache_write), output: u.outputTokens ?? 0, cache_read, cache_write, nano_aiu: u.copilotUsage?.totalNanoAiu ?? 0 },
      owned: !session || !u.accounting?.sourceSessionId || u.accounting.sourceSessionId === session,
      ...who,
    })
  }
  return attachTools(out, copilotTools(events), (r) => r.agentId)
}

/** The events of a session's log that requests and subagents are read from (the log can be tens of MB: other lines are skipped unparsed). */
export const sessionEvents = (dir, session) => readJsonl(join(dir, session, 'events.jsonl'), (line) => EVENT_TYPES.some((t) => line.includes(t)))

/** The requests in a session's event log. */
export const sessionRequests = (dir, session) => requestsOf(sessionEvents(dir, session), session)

// ---------- Claude Code ----------
/** Claude Code sessions whose id ends with the suffix, in any project under projectsDir. */
export function findClaudeSessions(projectsDir, suffix) {
  return list(projectsDir).flatMap((project) =>
    list(join(projectsDir, project))
      .filter((f) => f.endsWith(`${suffix}.jsonl`))
      .map((f) => ({ dir: join(projectsDir, project), session: f.slice(0, -'.jsonl'.length) })),
  )
}

/**
 * The model requests in one Claude Code transcript, one per API request id: id, harness ('claude'), model, effort (the
 * response's own, else the api-request entry that preceded it), tokens (input, output, cache_read, cache_write,
 * cache_write_1h: the part of cache_write that went to the 1-hour cache, output_unknown), ts (its start: the api-request
 * entry before its first entry, else that entry), end (the latest entry) and tools (the busy spans of the tools it
 * called, tool_use to tool_result, WAITING_TOOLS left out). Output tokens are known only once a response ends (an entry
 * with a stop_reason), which subagent transcripts don't record: such a request counts as output_unknown. For the same
 * reason end is approximate: the last entry written stands in for the end of the response.
 */
export function claudeRequestsOf(entries) {
  const byId = new Map()
  const calls = new Map()
  let effort = 'unknown'
  let sent = null
  for (const e of entries) {
    if (e.type === 'api-request') {
      effort = e.params?.output_config?.effort ?? effort
      if (e.timestamp) sent = e.timestamp
      continue
    }
    const blocks = Array.isArray(e.message?.content) ? e.message.content : []
    if (e.type === 'user' && e.timestamp)
      for (const b of blocks) {
        const call = b?.type === 'tool_result' ? calls.get(b.tool_use_id) : null
        if (!call) continue
        calls.delete(b.tool_use_id)
        call.request.tools.push([msAt(call.at), msAt(e.timestamp)])
      }
    if (e.type !== 'assistant' || !e.message?.usage || !e.timestamp) continue
    const model = e.message.model
    if (!model || model.startsWith('<')) continue
    // A response is written as several entries (one per content block); keep the first time and the final usage.
    const id = e.requestId ?? e.message.id ?? `${e.timestamp}:${byId.size}`
    const prev = byId.get(id)
    const final = Boolean(e.message.stop_reason)
    const end = prev && prev.end > e.timestamp ? prev.end : e.timestamp
    const ts = prev?.ts ?? (sent && sent <= e.timestamp ? sent : e.timestamp)
    if (!prev) sent = null
    const r = prev?.final && !final ? prev : { id, harness: 'claude', ts, end, model, effort: prev?.effort ?? e.effort ?? effort, usage: e.message.usage, final, tools: prev?.tools ?? [] }
    r.end = end
    byId.set(id, r)
    for (const b of blocks) if (b?.type === 'tool_use' && b.id && !WAITING_TOOLS.has(b.name)) calls.set(b.id, { at: e.timestamp, request: r })
  }
  return [...byId.values()].map(({ usage: u, final, ...r }) => ({
    ...r,
    tokens: {
      input: u.input_tokens ?? 0,
      output: final ? (u.output_tokens ?? 0) : 0,
      cache_read: u.cache_read_input_tokens ?? 0,
      cache_write: u.cache_creation_input_tokens ?? 0,
      cache_write_1h: u.cache_creation?.ephemeral_1h_input_tokens ?? 0,
      output_unknown: final ? 0 : 1,
    },
  }))
}

/** Every transcript of a Claude Code session: its own thread, its subagents and its workflow agents, with a label for each. */
export function claudeSources(dir, session) {
  const root = join(dir, session)
  const sources = [{ file: join(dir, `${session}.jsonl`), kind: 'main', label: 'main' }]
  const sub = join(root, 'subagents')
  for (const f of list(sub).filter((f) => /^agent-[\w-]+\.jsonl$/.test(f))) {
    const meta = readJson(join(sub, f.replace(/\.jsonl$/, '.meta.json'))) ?? {}
    sources.push({ file: join(sub, f), kind: 'subagent', label: label([meta.agentType, meta.description].filter(Boolean).join(': ') || f) })
  }
  const wfs = join(sub, 'workflows')
  for (const wf of list(wfs)) {
    const name = readJson(join(root, 'workflows', `${wf}.json`))?.workflowName ?? wf
    const labels = new Map(
      list(join(wfs, wf)).includes('journal.jsonl')
        ? readJsonl(join(wfs, wf, 'journal.jsonl'))
            .filter((e) => e.type === 'started' && e.agentId)
            .map((e) => [e.agentId, e.label ?? e.phase ?? e.agentId])
        : [],
    )
    for (const f of list(join(wfs, wf)).filter((f) => /^agent-[\w-]+\.jsonl$/.test(f))) {
      const id = f.slice('agent-'.length, -'.jsonl'.length)
      sources.push({ file: join(wfs, wf, f), kind: 'workflow', label: label(`${name}:${labels.get(id) ?? id}`) })
    }
  }
  return sources.filter((s) => existsSync(s.file))
}

// Tokens are summed field by field: a Copilot agent's carry nano_aiu (AI credits), a Claude Code agent's
// cache_write_1h and output_unknown (requests whose output count was not recorded) instead.
const ZERO = () => ({})
const add = (t, r) => {
  for (const [k, v] of Object.entries(r.tokens)) t[k] = (t[k] ?? 0) + (v ?? 0)
}

const pad2 = (n) => String(n).padStart(2, '0')
function msAt(t) {
  return t ? Date.parse(t) : NaN
}

/**
 * An agent's time in ms: its recorded active_ms (from version 4 on its busy time; versions 2 and 3 stored its first
 * request to the end of its last), else, for a v1 trace, its first request to its last request's start. 0 when its times
 * are missing, never negative.
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
 * earlier of its claim and the previous step's close (in close order, gates included; the run's start for the first) to
 * its close; each gate's wait, armed to resolved (null unless both are known); the human wait, summed over resolved human
 * gates; and the run's elapsed time, its start to its last close (null while nothing is closed). The start is startedAt
 * (an issue without steps: its first claim), else its creation.
 */
export function timingOf({ createdAt, startedAt, startFrom, steps }) {
  const at = msAt
  const ok = Number.isFinite
  const begin = startedAt ?? createdAt ?? null
  const beginFrom = startedAt ? (startFrom ?? 'created') : 'created'
  const closed = steps.filter((s) => s.closedAt).toSorted((a, b) => at(a.closedAt) - at(b.closedAt))
  const out = []
  closed.forEach((s, i) => {
    if (s.type === 'gate') return
    const close = at(s.closedAt)
    const prev = i ? { t: closed[i - 1].closedAt, from: 'previous close' } : { t: begin, from: beginFrom }
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
  const elapsed = last - at(begin)
  return {
    start: begin,
    start_from: beginFrom,
    elapsed_ms: ok(elapsed) ? elapsed : null,
    human_wait_ms: gates.filter((g) => g.type === 'human' && g.wait_ms != null).reduce((n, g) => n + g.wait_ms, 0),
    steps: out,
    gates,
  }
}

/**
 * The trace of a run from its bd record, the Copilot session logs under sessionsDir and the Claude Code transcripts under
 * projectsDir (either may be left out, and its harness's sessions are then missing).
 * record: { run, createdAt, startedAt?, startFrom?, steps: [{ id, closedAt | null, startedAt?, type?, gate?: { type, armedAt } }], actors: [string] }
 */
export function trace(record, { sessionsDir, projectsDir, now = new Date(), birthOf = (file) => statSync(file).birthtimeMs }) {
  const closed = record.steps.filter((s) => s.closedAt).sort((a, b) => a.closedAt.localeCompare(b.closedAt))
  const sessions = []
  const missing = []
  // Agent actors of a harness trace-run does not read (Codex): their work is not counted.
  const untraced = []
  const seenSessions = new Set()
  // A resumed or forked Copilot session starts with a copy of its parent's records (same API call ids): count each
  // request once, for the session that made it (owned), else the first one read.
  const byId = new Map()
  // A resumed or forked Claude Code session starts with a copy of its parent's requests (same ids and times): count each
  // request once, for the session that made it: the one that started first or, on a tie (a fork; transcripts have no
  // fork marker), the one whose transcript file was created first, else (no birth time on this filesystem) the one with
  // more requests.
  const claudeRead = []
  for (const actor of new Set(record.actors)) {
    const h = harnessOf(actor)
    if (!h) {
      if (AGENT_SESSION.test(actor) && !untraced.includes(actor)) untraced.push(actor)
      continue
    }
    const dir = h.harness === 'copilot' ? sessionsDir : projectsDir
    const found = !dir ? [] : h.harness === 'copilot' ? findSessions(dir, h.suffix) : findClaudeSessions(dir, h.suffix)
    if (!found.length && !missing.some((m) => harnessOf(m)?.suffix === h.suffix && harnessOf(m)?.harness === h.harness)) missing.push(actor)
    for (const { dir: d, session } of found) {
      if (seenSessions.has(session)) continue
      seenSessions.add(session)
      sessions.push({ actor, session, harness: h.harness })
      if (h.harness === 'copilot') {
        for (const r of sessionRequests(d, session)) {
          const prev = byId.get(r.id)
          if (!prev || (r.owned && !prev.owned)) byId.set(r.id, { ...r, actor })
        }
        continue
      }
      const rs = claudeSources(d, session).flatMap((src) => claudeRequestsOf(readJsonl(src.file)).map((r) => ({ ...r, actor, kind: src.kind, label: src.label })))
      let born = 0
      try {
        born = birthOf(join(d, `${session}.jsonl`)) || 0
      } catch {}
      claudeRead.push({ start: rs.reduce((m, r) => (r.ts < m ? r.ts : m), '\uffff'), born, rs })
    }
  }
  const seen = new Set()
  const byBirth = (a, b) => (a.born && b.born ? a.born - b.born : 0)
  const claude = []
  for (const { rs } of claudeRead.sort((a, b) => a.start.localeCompare(b.start) || byBirth(a, b) || b.rs.length - a.rs.length))
    for (const r of rs) {
      if (seen.has(r.id)) continue
      seen.add(r.id)
      claude.push(r)
    }
  const requests = [...byId.values(), ...claude].sort((a, b) => a.ts.localeCompare(b.ts))
  const begin = record.startedAt ?? record.createdAt

  const steps = new Map(closed.map((s) => [s.id, { step: s.id, closed_at: s.closedAt, agents: new Map() }]))
  const totals = new Map()
  // Each agent's busy spans: its requests and the tools they ran.
  const spans = new Map()
  let outside = 0
  for (const r of requests) {
    const step = r.ts >= begin ? closed.find((s) => s.closedAt >= r.ts) : undefined
    if (!step) {
      outside++
      continue
    }
    const key = [r.actor, r.kind, r.label, r.model, r.effort].join('\0')
    const agents = steps.get(step.id).agents
    const end = r.end ?? r.ts
    const a = agents.get(key) ?? {
      actor: r.actor,
      harness: r.harness,
      kind: r.kind,
      label: r.label,
      model: r.model,
      effort: r.effort,
      requests: 0,
      tokens: ZERO(),
      first: r.ts,
      last: r.ts,
      end,
    }
    a.requests++
    add(a.tokens, r)
    if (r.ts < a.first) a.first = r.ts
    if (r.ts > a.last) a.last = r.ts
    if (end > a.end) a.end = end
    spans.set(a, [...(spans.get(a) ?? []), [msAt(r.ts), msAt(end)], ...(r.tools ?? [])])
    agents.set(key, a)
    const tk = `${r.harness}\0${r.model}\0${r.effort}`
    const t = totals.get(tk) ?? { harness: r.harness, model: r.model, effort: r.effort, requests: 0, active_ms: 0, tokens: ZERO() }
    t.requests++
    add(t.tokens, r)
    totals.set(tk, t)
  }
  for (const s of steps.values())
    for (const a of s.agents.values()) {
      a.active_ms = unionMs(spans.get(a))
      totals.get(`${a.harness}\0${a.model}\0${a.effort}`).active_ms += a.active_ms
    }

  return {
    version: 4,
    traced_at: now.toISOString(),
    run: record.run,
    sessions,
    missing,
    untraced,
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
  `in ${short((t.input ?? 0) + (t.cache_read ?? 0) + (t.cache_write ?? 0))} (cache read ${short(t.cache_read ?? 0)}), out ${short(t.output ?? 0)}` +
  (t.output_unknown ? ` + ${t.output_unknown} req unknown` : '') +
  (typeof t.nano_aiu === 'number' ? `, ${(t.nano_aiu / 1e9).toFixed(1)} credits` : '')

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
      (t.untraced?.length ? `; harness not traced: ${t.untraced.join(', ')}` : '') +
      (t.open_steps.length ? `; open steps not traced: ${t.open_steps.map(step).join(', ')}` : ''),
    `Time: agents ${fmtDuration(agentMs)} (${(t.version ?? 1) >= 4 ? 'busy time per agent and step: model requests and the tools they ran, summed' : 'first to last request per agent and step, summed'}; approximate), ` +
      `human wait ${fmtDuration(t.timing?.human_wait_ms)}, elapsed ${fmtDuration(t.timing?.elapsed_ms)} (${t.timing?.start_from === 'claim' ? 'first claim' : 'created'} to last close; includes idle gaps)`,
    ...t.steps.map(
      (s) => `- ${step(s.step)} (elapsed ${elapsed(s.step)}): ${s.agents.map((a) => `${a.label} (${a.model}, ${a.effort}, ${a.requests} req, ${fmtDuration(activeMs(a))})`).join('; ')}`,
    ),
    ...(t.totals.length
      ? ['Totals:', ...t.totals.map((x) => `- ${x.harness ? `${x.harness} ` : ''}${x.model}, ${x.effort}: ${x.requests} req, ${fmtDuration(x.active_ms)}, ${fmtTokens(x.tokens)}`)]
      : ['No model requests found.']),
  ].join('\n')
}

// ---------- bd ----------
const RUN_ID = /^[a-z0-9]+(-[a-z0-9]+)+(\.[a-z0-9-]+)*$/
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
 * The run's bd record from bd(args): when it was created and started, when each step was claimed and closed (and, for
 * gates, armed), and every actor in its history. A step counts as closed only while it is (a reopened one is open again);
 * an issue without steps is its own only step, and starts at its first claim (an issue is often filed long before anyone
 * works on it), else at its creation; a run starts at its creation.
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
  const stepless = !steps.length
  if (stepless) {
    const self = bd(['show', run])
    steps.push(stepFrom({ ...self, id: run }, closedAt(self.status, own)))
  }
  const createdAt = own.find((e) => e.issue_id === run && e.op === 'created')?.ts
  if (!createdAt) throw new Error(`no created event for ${run}`)
  const claimed = stepless
    ? own
        .filter((e) => e.issue_id === run && e.op === 'claimed' && e.ts)
        .map((e) => e.ts)
        .sort()[0]
    : undefined
  const start = claimed && claimed >= createdAt ? { startedAt: claimed, startFrom: 'claim' } : { startedAt: createdAt, startFrom: 'created' }
  return { run, createdAt, ...start, steps, actors: own.map((e) => e.actor).filter(Boolean) }
}

/** Where each harness keeps its sessions: --sessions (Copilot) and --projects (Claude Code), else their defaults. */
export const logDirs = (opt, env = process.env) => ({
  sessionsDir: opt('--sessions') ?? join(env.COPILOT_HOME ?? join(homedir(), '.copilot'), 'session-state'),
  projectsDir: opt('--projects') ?? join(env.CLAUDE_CONFIG_DIR ?? join(homedir(), '.claude'), 'projects'),
})

function main(argv) {
  const valued = ['--sessions', '--projects', '--root', '--actor']
  const opt = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined)
  const run = argv.find((a, i) => !a.startsWith('--') && !valued.includes(argv[i - 1]))
  if (!run) throw new Error('usage: trace-run.mjs <run> [--root <checkout>] [--sessions <dir>] [--projects <dir>] [--actor <name>] [--write] [--summary]')
  const root = opt('--root')
  const result = trace(readRecord(run, bdRunner(root)), logDirs(opt))
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
