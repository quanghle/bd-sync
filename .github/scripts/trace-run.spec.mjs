import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import { activeMs, copilotTools, findSessions, fmtDuration, minus, readRecord, requestsOf, sessionSuffix, summarize, timingOf, trace, unionMs } from './trace-run.mjs'

const SESSION = '6f26e090-4089-4a32-bdd2-c49ba9c91d0b'
const ACTOR = 'Quang Le/copilot-a9c91d0b'
const SECRET = 'bd_live_SECRET_TOKEN_must_not_leak'
const WF = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
const MODEL = 'claude-opus-5.5'

// A session.usage_record event: the record's time is the end of the request. inputTokens counts the cache tokens too.
const use = (end, id, { agentId, effort = 'medium', model = MODEL, input = 1, output = 1, cr = 0, cw = 0, duration = 1000, nano = 0, source = SESSION } = {}) => ({
  type: 'session.usage_record',
  timestamp: end,
  ...(agentId ? { agentId } : {}),
  data: {
    usage: {
      model,
      inputTokens: input + cr + cw,
      outputTokens: output,
      cacheReadTokens: cr,
      cacheWriteTokens: cw,
      duration,
      ...(effort ? { reasoningEffort: effort } : {}),
      apiCallId: id,
      accounting: { sourceSessionId: source, usageId: id },
      copilotUsage: { totalNanoAiu: nano },
    },
  },
})
const started = (agentId, data) => ({ type: 'subagent.started', timestamp: '2026-10-15T10:00:30Z', agentId, data: { model: MODEL, ...data } })
const jsonl = (file, entries) => writeFileSync(file, entries.map((e) => JSON.stringify(e)).join('\n') + '\n{not json\n')
const writeSession = (sessions, id, entries) => {
  mkdirSync(join(sessions, id), { recursive: true })
  jsonl(join(sessions, id, 'events.jsonl'), entries)
}

let sessions
beforeEach(() => {
  sessions = mkdtempSync(join(tmpdir(), 'trace-run-'))
  writeSession(sessions, SESSION, [
    { type: 'user.message', timestamp: '2026-10-15T10:00:00Z', data: { content: SECRET } },
    use('2026-10-15T09:59:01Z', 'r0'), // before the run: left out
    use('2026-10-15T10:01:02Z', 'r1', { input: 10, output: 300, cr: 5, cw: 7, nano: 2_000_000_000 }),
    use('2026-10-15T10:20:01Z', 'r2', { effort: 'high', input: 20, output: 40 }),
    use('2026-10-15T11:00:01Z', 'r4'), // after the last close: left out
    started('a1', { agentName: 'general-purpose', agentDisplayName: 'Review the diff '.repeat(10) }),
    { type: 'subagent.configured', timestamp: '2026-10-15T10:00:31Z', agentId: 'a1', data: { reasoningEffort: 'low' } },
    use('2026-10-15T10:21:01Z', 's1', { agentId: 'a1', effort: null, input: 100, output: 8, duration: 0 }),
    started('w1', { agentName: 'task', agentDisplayName: 'judge', workflowRunId: WF }),
    use('2026-10-15T10:22:00Z', 'w1', { agentId: 'w1', effort: 'xhigh', model: 'gpt-6-astra', input: 50, output: 9 }),
    { type: 'system.notification', timestamp: '2026-10-15T10:23:00Z', data: { content: `<system_notification>\nWorkflow "score-issue" run ${WF} reached terminal status completed.` } },
  ])
})
afterEach(() => rmSync(sessions, { recursive: true, force: true }))

const record = {
  run: 'squid-x.1',
  createdAt: '2026-10-15T10:00:00Z',
  steps: [
    { id: 'squid-x.1.review', closedAt: '2026-10-15T10:30:00Z' },
    { id: 'squid-x.1.requirements', closedAt: '2026-10-15T10:10:00Z' },
    { id: 'squid-x.1.score', closedAt: null },
  ],
  actors: [ACTOR, ACTOR, 'Quang Le', 'Quang Le/copilot-deadbeef'],
}

describe('trace-run', () => {
  it('maps an agent actor to its session by the last 8 hex digits', () => {
    expect(sessionSuffix(ACTOR)).toBe('a9c91d0b')
    expect(sessionSuffix('Quang Le/copilot-a9c91d0b.w1')).toBe('a9c91d0b')
    expect(sessionSuffix('Quang Le/copilot-a9c91d0b.Worker_1.agent-x')).toBe('a9c91d0b')
    expect(sessionSuffix('Quang Le')).toBeNull()
    expect(sessionSuffix('Quang Le/claude-a9c91d0b')).toBeNull()
    expect(sessionSuffix('Quang Le/copilot-../../etc')).toBeNull()
    expect(findSessions(sessions, 'a9c91d0b').map((s) => s.session)).toEqual([SESSION])
    expect(findSessions(sessions, 'deadbeef')).toEqual([])
  })

  it('reads a request from its usage record: input without its cache parts, start from the duration, credits', () => {
    const rs = requestsOf([use('2026-10-15T10:01:02.500Z', 'r1', { input: 10, output: 300, cr: 5, cw: 7, duration: 1500, nano: 2_500_000_000 })])
    expect(rs).toEqual([
      {
        id: 'r1',
        harness: 'copilot',
        agentId: '',
        ts: '2026-10-15T10:01:01.000Z',
        end: '2026-10-15T10:01:02.500Z',
        model: MODEL,
        effort: 'medium',
        tokens: { input: 10, output: 300, cache_read: 5, cache_write: 7, nano_aiu: 2_500_000_000 },
        owned: true,
        kind: 'main',
        label: 'main',
        tools: [],
      },
    ])
    expect(requestsOf([use('2026-10-15T10:01:02Z', 'x', { effort: null })])[0].effort).toBe('unknown')
    expect(requestsOf([{ type: 'session.usage_record', timestamp: '2026-10-15T10:00:00Z', data: { usage: {} } }])).toEqual([])
  })

  it("labels a subagent's and a workflow agent's requests, with the effort it was configured with when the record has none", () => {
    const rs = requestsOf([
      started('a1', { agentName: 'general-purpose', agentDisplayName: 'review' }),
      { type: 'subagent.configured', agentId: 'a1', data: { reasoningEffort: 'low' } },
      started('w1', { agentName: 'task', agentDisplayName: 'claim', workflowRunId: WF }),
      use('2026-10-15T10:01:00Z', 'a', { agentId: 'a1', effort: null }),
      use('2026-10-15T10:01:01Z', 'b', { agentId: 'w1' }),
      use('2026-10-15T10:01:02Z', 'c', { agentId: 'gone', effort: null }),
      { type: 'system.notification', data: { content: `Workflow "plan-implement-review" run ${WF} reached terminal status completed.` } },
    ])
    expect(rs.map((r) => [r.kind, r.label, r.effort])).toEqual([
      ['subagent', 'general-purpose: review', 'low'],
      ['workflow', 'plan-implement-review:claim', 'medium'],
      ['subagent', 'gone', 'unknown'],
    ])
    // A workflow whose completion is not logged yet still gets a label.
    expect(requestsOf([started('w1', { agentName: 'task', agentDisplayName: 'claim', workflowRunId: WF }), use('2026-10-15T10:01:01Z', 'b', { agentId: 'w1' })])[0].label).toBe('workflow:claim')
  })

  it('marks a record another session made as not owned', () => {
    expect(requestsOf([use('2026-10-15T10:01:00Z', 'a', { source: 'other' })], SESSION)[0].owned).toBe(false)
    expect(requestsOf([use('2026-10-15T10:01:00Z', 'a', { source: SESSION })], SESSION)[0].owned).toBe(true)
  })

  it('puts each request in the first step closed at or after it, per agent, model and effort', () => {
    const t = trace(record, { sessionsDir: sessions, now: new Date('2026-10-15T12:00:00Z') })
    expect(t.steps.map((s) => s.step)).toEqual(['squid-x.1.requirements', 'squid-x.1.review'])
    const [requirements, review] = t.steps
    expect(requirements.agents).toEqual([
      {
        actor: ACTOR,
        harness: 'copilot',
        kind: 'main',
        label: 'main',
        model: MODEL,
        effort: 'medium',
        requests: 1,
        tokens: { input: 10, output: 300, cache_read: 5, cache_write: 7, nano_aiu: 2_000_000_000 },
        first: '2026-10-15T10:01:01.000Z',
        last: '2026-10-15T10:01:01.000Z',
        end: '2026-10-15T10:01:02Z',
        active_ms: 1000,
      },
    ])
    expect(review.agents.map((a) => [a.kind, a.label, a.model, a.effort, a.requests])).toEqual([
      ['main', 'main', MODEL, 'high', 1],
      ['subagent', expect.stringMatching(/^general-purpose: Review the diff .*…$/), MODEL, 'low', 1],
      ['workflow', 'score-issue:judge', 'gpt-6-astra', 'xhigh', 1],
    ])
    expect(review.agents[1].label.length).toBeLessThanOrEqual(80)
    expect(t.outside_requests).toBe(2)
    expect(t.open_steps).toEqual(['squid-x.1.score'])
    expect(t.totals.find((x) => x.model === MODEL && x.effort === 'medium')).toMatchObject({ requests: 1, active_ms: 1000 })
    expect(t.version).toBe(4)
    expect(t.timing).toMatchObject({ elapsed_ms: 30 * 60_000, human_wait_ms: 0, gates: [] })
    expect(t.timing.steps.map((s) => [s.step, s.start_from, s.elapsed_ms])).toEqual([
      ['squid-x.1.requirements', 'created', 10 * 60_000],
      ['squid-x.1.review', 'previous close', 20 * 60_000],
    ])
  })

  it('times an agent by its requests, not the idle time between them, within a step', () => {
    writeSession(sessions, SESSION, [
      use('2026-10-15T10:21:01Z', 's1', { agentId: 'a1', duration: 1000 }),
      use('2026-10-15T10:24:05Z', 's2', { agentId: 'a1', duration: 6000 }),
      started('a1', { agentName: 'general-purpose', agentDisplayName: 'review' }),
    ])
    const t = trace(record, { sessionsDir: sessions })
    const agent = t.steps.find((s) => s.step === 'squid-x.1.review').agents[0]
    expect(agent).toMatchObject({ requests: 2, first: '2026-10-15T10:21:00.000Z', last: '2026-10-15T10:23:59.000Z', end: '2026-10-15T10:24:05Z' })
    expect(agent.active_ms).toBe(7_000)
    expect(t.totals.find((x) => x.effort === 'medium').active_ms).toBe(7_000)
  })

  it('counts the tools a request ran as busy, but not waits on a person, a permission prompt or another agent', () => {
    const tool = (name, id, start, end, agentId) => [
      { type: 'tool.execution_start', timestamp: start, ...(agentId ? { agentId } : {}), data: { toolCallId: id, toolName: name, arguments: SECRET } },
      { type: 'tool.execution_complete', timestamp: end, ...(agentId ? { agentId } : {}), data: { toolCallId: id, result: SECRET } },
    ]
    writeSession(sessions, SESSION, [
      use('2026-10-15T10:21:01Z', 'm1', { duration: 1000 }),
      ...tool('bash', 'b1', '2026-10-15T10:21:01Z', '2026-10-15T10:22:01Z'), // a 60 s build
      { type: 'permission.requested', timestamp: '2026-10-15T10:21:11Z', data: { permissionRequest: { toolCallId: 'b1' } } },
      { type: 'permission.completed', timestamp: '2026-10-15T10:21:31Z', data: { toolCallId: 'b1' } }, // 20 s of it a person
      ...tool('ask_user', 'q1', '2026-10-15T10:22:02Z', '2026-10-15T10:25:00Z'),
      started('a1', { agentName: 'general-purpose', agentDisplayName: 'review', toolCallId: 't1' }),
      ...tool('task', 't1', '2026-10-15T10:25:01Z', '2026-10-15T10:27:00Z'), // a foreground subagent: its own agent
      ...tool('bash', 'b2', '2026-10-15T10:25:30Z', '2026-10-15T10:25:40Z', 'a1'),
      use('2026-10-15T10:25:30Z', 's1', { agentId: 'a1', duration: 2000 }),
      use('2026-10-15T10:29:01Z', 'm2', { duration: 1000 }), // after ten idle minutes
    ])
    const t = trace(record, { sessionsDir: sessions })
    const [main, sub] = t.steps.find((s) => s.step === 'squid-x.1.review').agents
    expect(main).toMatchObject({ kind: 'main', requests: 2, active_ms: 1_000 + 40_000 + 1_000 })
    expect(sub).toMatchObject({ kind: 'subagent', requests: 1, active_ms: 2_000 + 10_000 })
    expect(JSON.stringify(t)).not.toContain(SECRET)
  })

  it('reads tool spans from the events, each for its agent', () => {
    const ev = (type, ts, data, agentId) => ({ type, timestamp: ts, ...(agentId ? { agentId } : {}), data })
    const ms = (t) => Date.parse(t)
    expect(
      copilotTools([
        ev('tool.execution_start', '2026-10-15T10:00:00Z', { toolCallId: 'a', toolName: 'bash' }, 'w1'),
        ev('tool.execution_start', '2026-10-15T10:00:01Z', { toolCallId: 'b', toolName: 'read_agent' }),
        ev('tool.execution_start', '2026-10-15T10:00:02Z', { toolCallId: 'c', toolName: 'view' }), // never completes
        ev('tool.execution_complete', '2026-10-15T10:00:05Z', { toolCallId: 'a' }, 'w1'),
        ev('tool.execution_complete', '2026-10-15T10:00:09Z', { toolCallId: 'b' }),
      ]),
    ).toEqual([{ agent: 'w1', span: [ms('2026-10-15T10:00:00Z'), ms('2026-10-15T10:00:05Z')] }])
  })

  it('measures intervals once where they overlap, and cuts holes out of one', () => {
    expect(unionMs([])).toBe(0)
    expect(unionMs([[0, 10], [5, 20], [30, 40], [40, 41], [50, 50], [NaN, 60]])).toBe(31)
    expect(minus([0, 100], [[10, 20], [90, 200], [-5, 1]])).toEqual([[1, 10], [20, 90]])
    expect(minus([0, 100], [[20, Infinity]])).toEqual([[0, 20]])
  })

  it('lists agent actors without a session log here as missing, and ignores people', () => {
    const t = trace(record, { sessionsDir: sessions })
    expect(t.missing).toEqual(['Quang Le/copilot-deadbeef'])
    // A session's sub-actor is the same missing session.
    expect(trace({ ...record, actors: [...record.actors, 'Quang Le/copilot-deadbeef.w1'] }, { sessionsDir: sessions }).missing).toEqual(['Quang Le/copilot-deadbeef'])
    expect(t.sessions).toEqual([{ actor: ACTOR, session: SESSION, harness: 'copilot' }])
    expect(trace({ ...record, actors: ['Quang Le'] }, { sessionsDir: join(sessions, 'nope') }).steps).toEqual([])
  })

  it('summarizes who did what per step, with totals and what could not be traced', () => {
    const text = summarize(trace(record, { sessionsDir: sessions }))
    expect(text).toContain('not on this machine: Quang Le/copilot-deadbeef')
    expect(text).toContain('open steps not traced: score')
    expect(text).toContain('- requirements (elapsed 10m 00s): main (claude-opus-5.5, medium, 1 req, 1s)')
    expect(text).toContain('score-issue:judge (gpt-6-astra, xhigh, 1 req, 1s)')
    expect(text).toContain('- copilot claude-opus-5.5, medium: 1 req, 1s, in 22 (cache read 5), out 300, 2.0 credits')
    expect(text).toMatch(/^Time: agents .* \(.*approximate\), human wait .*, elapsed .*idle gaps/m)
    expect(text).not.toContain(SECRET)
  })

  it('counts a request copied into a resumed session once, for the session that made it', () => {
    const copy = use('2026-10-15T10:01:02Z', 'r1', { input: 10, output: 300, cr: 5, cw: 7, nano: 2_000_000_000 })
    writeSession(sessions, '11111111-2222-3333-4444-5555deadbeef', [copy, use('2026-10-15T10:25:01Z', 'n1', { effort: 'low', source: '11111111-2222-3333-4444-5555deadbeef' })])
    // The copy is read first (its actor comes first), yet belongs to the session that made it.
    const t = trace({ ...record, actors: ['Quang Le/copilot-deadbeef', ACTOR] }, { sessionsDir: sessions })
    const requirements = t.steps.find((s) => s.step === 'squid-x.1.requirements')
    expect(requirements.agents.map((a) => [a.actor, a.requests])).toEqual([[ACTOR, 1]])
    const review = t.steps.find((s) => s.step === 'squid-x.1.review')
    expect(review.agents.find((a) => a.kind === 'main' && a.effort === 'low').actor).toBe('Quang Le/copilot-deadbeef')
    expect(t.missing).toEqual([])
  })

  it('keeps a copied request whose owner session is not on this machine', () => {
    writeSession(sessions, '11111111-2222-3333-4444-5555deadbeef', [use('2026-10-15T10:01:02Z', 'gone', { source: 'someone-else' })])
    const t = trace({ ...record, actors: ['Quang Le/copilot-deadbeef'] }, { sessionsDir: sessions })
    expect(t.steps.flatMap((s) => s.agents).map((a) => a.requests)).toEqual([1])
  })

  it('puts a request made at the exact close time in the step that closed', () => {
    const t = trace(
      { ...record, createdAt: '2026-10-15T10:00:00.000Z', steps: [{ id: 'squid-x.1.a', closedAt: '2026-10-15T10:01:02Z' }, { id: 'squid-x.1.b', closedAt: '2026-10-15T10:30:00.000Z' }] },
      { sessionsDir: sessions },
    )
    expect(t.steps.map((s) => [s.step, s.agents.reduce((n, a) => n + a.requests, 0)])).toEqual([
      ['squid-x.1.a', 1],
      ['squid-x.1.b', 3],
    ])
  })

  it('reads a trace without end times in its summary', () => {
    const t = trace(record, { sessionsDir: sessions })
    for (const s of t.steps)
      for (const a of s.agents) {
        delete a.end
        delete a.active_ms
      }
    expect(summarize({ ...t, timing: undefined })).toContain('- requirements (elapsed –): main (claude-opus-5.5, medium, 1 req, 0s)')
  })

  it('lists agent actors of a harness it does not read as untraced', () => {
    const t = trace({ ...record, actors: [...record.actors, 'Quang Le/codex-9fba3d50', 'Quang Le/codex-9fba3d50', 'bd-serve'] }, { sessionsDir: sessions })
    expect(t.untraced).toEqual(['Quang Le/codex-9fba3d50'])
    expect(summarize(t)).toContain('; harness not traced: Quang Le/codex-9fba3d50')
  })

  it('summarizes a stored trace before version 4 with its own definition of agent time', () => {
    const t = trace(record, { sessionsDir: sessions })
    expect(summarize({ ...t, version: 3 })).toContain('(first to last request per agent and step, summed; approximate)')
    expect(summarize(t)).toContain('(busy time per agent and step: model requests and the tools they ran, summed; approximate)')
  })

  it('never copies session content into the result', () => {
    expect(JSON.stringify(trace(record, { sessionsDir: sessions }))).not.toContain(SECRET)
  })
})

const at = (hm) => `2026-10-15T${hm}:00.000Z`
const step = (id, closedAt, startedAt = null) => ({ id, closedAt, startedAt, type: 'task', gate: null })
const gate = (id, type, armedAt, closedAt) => ({ id, closedAt, startedAt: null, type: 'gate', gate: { type, armedAt } })

describe('timingOf', () => {

	it('starts each step at the earlier of its claim and the previous close, or the run creation', () => {
		const t = timingOf({
			createdAt: at('10:00'),
			steps: [
				step('r.c', at('10:40'), at('10:15')), // claimed before the previous close: from the claim
				step('r.a', at('10:10')), // first, unclaimed: from the creation
				step('r.b', at('10:30'), at('10:29')), // claimed after the previous close: from that close
				step('r.d', at('10:50'), at('10:55')), // a claim after the close is ignored
				step('r.e', null, at('10:51')), // open: not timed
			],
		})
		expect(t.steps).toEqual([
			{ step: 'r.a', start: at('10:00'), start_from: 'created', closed_at: at('10:10'), elapsed_ms: 600_000 },
			{ step: 'r.b', start: at('10:10'), start_from: 'previous close', closed_at: at('10:30'), elapsed_ms: 1_200_000 },
			{ step: 'r.c', start: at('10:15'), start_from: 'claim', closed_at: at('10:40'), elapsed_ms: 1_500_000 },
			{ step: 'r.d', start: at('10:40'), start_from: 'previous close', closed_at: at('10:50'), elapsed_ms: 600_000 },
		])
		expect(t.elapsed_ms).toBe(50 * 60_000)
		expect(t.gates).toEqual([])
		expect(t.human_wait_ms).toBe(0)
	})

	it('reports gates apart, and sums the waits of resolved human gates', () => {
		const t = timingOf({
			createdAt: at('10:00'),
			steps: [
				step('r.implement', at('10:10')),
				gate('r.gate-design', 'human', at('10:05'), at('10:25')),
				step('r.score', at('10:30'), at('10:26')),
				gate('r.gate-forced', 'human', null, at('10:31')), // resolved without being armed
				gate('r.gate-open', 'human', at('10:31'), null), // not resolved yet
				gate('r.gate-timer', 'timer', at('10:00'), at('10:20')), // not a person
			],
		})
		// Gates aren't steps, but a gate's resolution bounds the next step's start.
		expect(t.steps.map((s) => [s.step, s.start_from, s.elapsed_ms])).toEqual([
			['r.implement', 'created', 600_000],
			['r.score', 'previous close', 300_000],
		])
		expect(t.gates).toEqual([
			{ gate: 'r.gate-design', type: 'human', armed_at: at('10:05'), resolved_at: at('10:25'), wait_ms: 1_200_000 },
			{ gate: 'r.gate-forced', type: 'human', armed_at: null, resolved_at: at('10:31'), wait_ms: null },
			{ gate: 'r.gate-open', type: 'human', armed_at: at('10:31'), resolved_at: null, wait_ms: null },
			{ gate: 'r.gate-timer', type: 'timer', armed_at: at('10:00'), resolved_at: at('10:20'), wait_ms: 1_200_000 },
		])
		expect(t.human_wait_ms).toBe(1_200_000)
		expect(t.elapsed_ms).toBe(31 * 60_000)
	})

	it('times an issue without steps from its first claim', () => {
		const t = timingOf({ createdAt: at('01:00'), startedAt: at('10:00'), startFrom: 'claim', steps: [step('r', at('10:13'), at('10:05'))] })
		expect(t).toMatchObject({ start: at('10:00'), start_from: 'claim', elapsed_ms: 13 * 60_000 })
		expect(t.steps).toEqual([{ step: 'r', start: at('10:00'), start_from: 'claim', closed_at: at('10:13'), elapsed_ms: 13 * 60_000 }])
	})

	it('has no elapsed time while nothing is closed, and reads records without the new step fields', () => {
		expect(timingOf({ createdAt: at('10:00'), steps: [step('r.a', null)] })).toEqual({ start: at('10:00'), start_from: 'created', elapsed_ms: null, human_wait_ms: 0, steps: [], gates: [] })
		expect(timingOf({ createdAt: at('10:00'), steps: [{ id: 'r.a', closedAt: at('10:01') }] }).steps).toEqual([
			{ step: 'r.a', start: at('10:00'), start_from: 'created', closed_at: at('10:01'), elapsed_ms: 60_000 },
		])
	})
})

describe('fmtDuration and activeMs', () => {
	it('formats durations in seconds, minutes or hours', () => {
		expect(fmtDuration(null)).toBe('–')
		expect(fmtDuration(undefined)).toBe('–')
		expect(fmtDuration(NaN)).toBe('–')
		expect(fmtDuration(0)).toBe('0s')
		expect(fmtDuration(59_400)).toBe('59s')
		expect(fmtDuration(59_600)).toBe('1m 00s')
		expect(fmtDuration(754_000)).toBe('12m 34s')
		expect(fmtDuration(7_380_000)).toBe('2h 03m')
	})

	it('uses the recorded active time, else last minus first for v1 agents, else 0', () => {
		expect(activeMs({ active_ms: 42, first: '2026-10-15T10:00:00Z', end: '2026-10-15T10:01:00Z' })).toBe(42)
		expect(activeMs({ first: '2026-10-15T10:00:00Z', end: '2026-10-15T10:01:00Z', last: '2026-10-15T10:00:30Z' })).toBe(60_000)
		expect(activeMs({ first: '2026-10-15T10:00:00Z', last: '2026-10-15T10:00:30Z' })).toBe(30_000)
		expect(activeMs({})).toBe(0)
		expect(activeMs({ first: '2026-10-15T10:01:00Z', last: '2026-10-15T10:00:00Z' })).toBe(0)
	})
})

describe('readRecord', () => {
	const events = {
		'squid-x.1': [
			{ issue_id: 'squid-x.1', op: 'created', ts: '2026-10-15T10:00:00.000Z', actor: 'Quang Le/copilot-a9c91d0b' },
		],
		'squid-x.1.requirements': [
			{ issue_id: 'squid-x.1.requirements', op: 'closed', ts: '2026-10-15T10:05:00.000Z', actor: 'Quang Le/copilot-a9c91d0b' },
		],
		'squid-x.1.review': [
			{ issue_id: 'squid-x.1.review', op: 'closed', ts: '2026-10-15T10:10:00.000Z', actor: 'Quang Le/copilot-a9c91d0b.agent-1' },
			{ issue_id: 'squid-x.1.review', op: 'reopened', ts: '2026-10-15T10:11:00.000Z', actor: 'Quang Le' },
		],
		'squid-x.1.review.1': [{ issue_id: 'squid-x.1.review.1', op: 'closed', ts: '2026-10-15T10:09:00.000Z', actor: 'Quang Le/copilot-0badc0de' }],
		'squid-x.1.gate-score-confirm': [{ issue_id: 'squid-x.1.gate-score-confirm', op: 'closed', ts: '2026-10-15T10:20:00.000Z', actor: 'Quang Le' }],
	}
	const fakeBd = (children, status = 'open') => {
		const calls = []
		const bd = (args) => {
			calls.push(args)
			if (args[0] === 'history') return events[args[1]] ?? []
			if (args[0] === 'list') return children
			if (args[0] === 'show') return { id: args[1], status }
			throw new Error(`unexpected ${args}`)
		}
		return { bd, calls }
	}

	it('reads the direct steps, without a limit, and only counts a step closed while it is', () => {
		const { bd, calls } = fakeBd([
			{ id: 'squid-x.1.requirements', status: 'closed', issue_type: 'task', started_at: '2026-10-15T10:01:00.000Z' },
			{ id: 'squid-x.1.review', status: 'open' }, // closed, then reopened
			{ id: 'squid-x.1.review.1', status: 'closed' }, // a finding under the review step
			{
				id: 'squid-x.1.gate-score-confirm',
				status: 'closed',
				issue_type: 'gate',
				closed_at: '2026-10-15T10:20:00.000Z',
				metadata: { gate: { type: 'human', armed_at: '2026-10-15T10:12:00.000Z' } },
			},
		])
		const r = readRecord('squid-x.1', bd)
		expect(calls).toContainEqual(['list', '--all', '-n', '0', '--parent', 'squid-x.1'])
		expect(r.createdAt).toBe('2026-10-15T10:00:00.000Z')
		// A run starts at its creation, whoever claimed it.
		expect(r).toMatchObject({ startedAt: '2026-10-15T10:00:00.000Z', startFrom: 'created' })
		expect(r.steps).toEqual([
			{ id: 'squid-x.1.requirements', closedAt: '2026-10-15T10:05:00.000Z', startedAt: '2026-10-15T10:01:00.000Z', type: 'task', gate: null },
			{ id: 'squid-x.1.review', closedAt: null, startedAt: null, type: null, gate: null },
			{
				id: 'squid-x.1.gate-score-confirm',
				closedAt: '2026-10-15T10:20:00.000Z',
				startedAt: null,
				type: 'gate',
				gate: { type: 'human', armedAt: '2026-10-15T10:12:00.000Z' },
			},
		])
		// The finding isn't a step, but the session that closed it is traced.
		expect(new Set(r.actors)).toEqual(new Set(['Quang Le/copilot-a9c91d0b', 'Quang Le/copilot-a9c91d0b.agent-1', 'Quang Le', 'Quang Le/copilot-0badc0de']))
	})

	it('makes an issue without steps its own only step', () => {
		expect(readRecord('squid-x.1', fakeBd([], 'open').bd).steps).toEqual([{ id: 'squid-x.1', closedAt: null, startedAt: null, type: null, gate: null }])
	})

	it('starts an issue without steps at its first claim, else at its creation', () => {
		const h = [
			{ issue_id: 'bd-sync-8gdf', op: 'created', ts: '2026-10-15T01:02:45.370Z', actor: 'Quang Le/codex-9fba3d50' },
			{ issue_id: 'bd-sync-8gdf', op: 'claimed', ts: '2026-10-15T22:10:01.482Z', actor: 'Quang Le/claude-249b6892' },
			{ issue_id: 'bd-sync-8gdf', op: 'released', ts: '2026-10-15T22:11:00.000Z', actor: 'Quang Le/claude-249b6892' },
			{ issue_id: 'bd-sync-8gdf', op: 'claimed', ts: '2026-10-15T22:12:00.000Z', actor: 'Quang Le/claude-249b6892' },
			{ issue_id: 'bd-sync-8gdf', op: 'closed', ts: '2026-10-15T22:22:59.375Z', actor: 'Quang Le/claude-249b6892' },
		]
		const bd = (events) => (args) => (args[0] === 'history' ? events : args[0] === 'list' ? [] : { id: args[1], status: 'closed' })
		expect(readRecord('bd-sync-8gdf', bd(h))).toMatchObject({ createdAt: '2026-10-15T01:02:45.370Z', startedAt: '2026-10-15T22:10:01.482Z', startFrom: 'claim' })
		expect(readRecord('bd-sync-8gdf', bd(h.filter((e) => e.op !== 'claimed')))).toMatchObject({ startedAt: '2026-10-15T01:02:45.370Z', startFrom: 'created' })
	})

	it('takes ids whose prefix has hyphens', () => {
		for (const id of ['bd-sync-8gdf', 'bd-sync-8gdf.review', 'bd-04ei']) {
			const bd = (args) => (args[0] === 'history' ? [{ issue_id: id, op: 'created', ts: '2026-10-15T10:00:00.000Z', actor: 'Quang Le' }] : args[0] === 'list' ? [] : { id, status: 'open' })
			expect(readRecord(id, bd).steps[0].id).toBe(id)
		}
	})

	it('refuses anything but a bd issue id', () => {
		for (const id of ['squid-x.1; rm -rf /', 'squid', '-bd-x', 'bd-x-', 'bd--x', 'Bd-x', 'bd-x y'])
			expect(() => readRecord(id, fakeBd([]).bd)).toThrow('not a bd issue id')
	})
})

describe('trace-run CLI', () => {
	let bin
	beforeEach(() => {
		bin = mkdtempSync(join(tmpdir(), 'trace-run-bd-'))
		// A stand-in for bd: answers the reads from a fixture and logs every call; `update` fails when FAIL_WRITE is set.
		writeFileSync(
			join(bin, 'bd'),
			`#!/bin/sh
echo "$*" >> "${bin}/calls"
case " $* " in
  *" update "*) [ -n "$FAIL_WRITE" ] && { echo "server unreachable" >&2; exit 8; }; exit 0 ;;
  *"history squid-x.1 "*) echo '[{"issue_id":"squid-x.1","op":"created","ts":"2026-10-15T10:00:00Z","actor":"${ACTOR}"}]' ;;
  *"history "*) echo '[{"op":"closed","ts":"2026-10-15T10:30:00Z","actor":"${ACTOR}"}]' ;;
  *" list "*) echo '[{"id":"squid-x.1.review","status":"closed"}]' ;;
esac
`,
		)
		chmodSync(join(bin, 'bd'), 0o755)
	})
	afterEach(() => rmSync(bin, { recursive: true, force: true }))

	const script = fileURLToPath(new URL('./trace-run.mjs', import.meta.url))
	const cli = (args, env = {}) => {
		try {
			return { code: 0, out: execFileSync('node', [script, ...args], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, ...env }, stdio: ['ignore', 'pipe', 'pipe'] }) }
		} catch (e) {
			return { code: e.status, out: e.stdout, err: e.stderr }
		}
	}

	it('stores the trace as the work metadata, as the given actor, in the given checkout', () => {
		const r = cli(['squid-x.1', '--root', '/repo', '--sessions', sessions, '--actor', 'Quang Le/copilot-a9c91d0b', '--write', '--summary'])
		expect(r.code).toBe(0)
		expect(r.out).toContain('- review (elapsed 30m 00s): main (claude-opus-5.5, medium, 1 req, 1s)')
		const update = readFileSync(join(bin, 'calls'), 'utf8').split('\n').find((l) => l.includes(' update '))
		expect(update).toMatch(/^-C \/repo update squid-x\.1 --set-metadata work=\{.*\} --actor Quang Le\/copilot-a9c91d0b$/)
		expect(update).not.toContain(SECRET)
	})

	it('reports a failure in one line, not a stack', () => {
		const r = cli(['squid-x.1; rm -rf /', '--sessions', sessions])
		expect(r.code).toBe(1)
		expect(r.err).toBe('trace-run: not a bd issue id: squid-x.1; rm -rf /\n')
	})

	it('still prints the trace when the write fails, and says why', () => {
		const r = cli(['squid-x.1', '--sessions', sessions, '--write', '--summary'], { FAIL_WRITE: '1' })
		expect(r.code).toBe(1)
		expect(r.out).toContain('Work trace: 1 session(s)')
		expect(r.err).toContain('could not store the work metadata on squid-x.1: server unreachable')
	})
})
