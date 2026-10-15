import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import { activeMs, findSessions, fmtDuration, readRecord, requestsOf, sessionSuffix, summarize, timingOf, trace } from './trace-run.mjs'

const SESSION = '6f26e090-4089-4a32-bdd2-c49ba9c91d0b'
const ACTOR = 'Quang Le/claude-a9c91d0b'
const SECRET = 'bd_live_SECRET_TOKEN_must_not_leak'

const req = (ts, model, effort) => ({ type: 'api-request', timestamp: ts, params: { model, output_config: { effort } } })
const res = (ts, id, model, usage, stop = 'end_turn', text = SECRET) => ({
	type: 'assistant',
	timestamp: ts,
	requestId: id,
	message: { model, stop_reason: stop, usage, content: [{ type: 'text', text }] },
})
const usage = (input, output, cache_read = 0, cache_write = 0) => ({
	input_tokens: input,
	output_tokens: output,
	cache_read_input_tokens: cache_read,
	cache_creation_input_tokens: cache_write,
})
const jsonl = (file, entries) => writeFileSync(file, entries.map((e) => JSON.stringify(e)).join('\n') + '\n{not json\n')

let projects
beforeEach(() => {
	projects = mkdtempSync(join(tmpdir(), 'trace-run-'))
	const dir = join(projects, '-Users-quang-Projects-squi')
	const sub = join(dir, SESSION, 'subagents')
	const wf = join(sub, 'workflows', 'wf_1')
	mkdirSync(wf, { recursive: true })
	mkdirSync(join(dir, SESSION, 'workflows'), { recursive: true })
	jsonl(join(dir, `${SESSION}.jsonl`), [
		{ type: 'user', timestamp: '2026-10-15T10:00:00Z', message: { content: SECRET } },
		req('2026-10-15T09:59:00Z', 'claude-opus-5-5', 'medium'),
		res('2026-10-15T09:59:01Z', 'r0', 'claude-opus-5-5', usage(1, 1)), // before the run: left out
		req('2026-10-15T10:01:00Z', 'claude-opus-5-5', 'medium'),
		// One request written as two entries: counted once, with the final entry's usage.
		res('2026-10-15T10:01:01Z', 'r1', 'claude-opus-5-5', usage(10, 3), null),
		res('2026-10-15T10:01:02Z', 'r1', 'claude-opus-5-5', usage(10, 300, 5, 7)),
		req('2026-10-15T10:20:00Z', 'claude-opus-5-5', 'high'),
		res('2026-10-15T10:20:01Z', 'r2', 'claude-opus-5-5', usage(20, 40)),
		res('2026-10-15T10:20:02Z', 'r3', '<synthetic>', usage(0, 0)), // not a model request
		req('2026-10-15T11:00:00Z', 'claude-opus-5-5', 'medium'),
		res('2026-10-15T11:00:01Z', 'r4', 'claude-opus-5-5', usage(1, 1)), // after the last close: left out
	])
	jsonl(join(sub, 'agent-a1.jsonl'), [
		req('2026-10-15T10:21:00Z', 'claude-opus-5-5', 'medium'),
		res('2026-10-15T10:21:01Z', 's1', 'claude-opus-5-5', usage(100, 8), null),
	])
	writeFileSync(join(sub, 'agent-a1.meta.json'), JSON.stringify({ agentType: 'general-purpose', description: 'Review the diff '.repeat(10) }))
	jsonl(join(wf, 'agent-w1.jsonl'), [res('2026-10-15T10:22:00Z', 'w1', 'claude-fable-5-1', usage(50, 9))])
	jsonl(join(wf, 'journal.jsonl'), [{ type: 'started', agentId: 'w1', label: 'judge', phase: 'Judge' }])
	writeFileSync(join(dir, SESSION, 'workflows', 'wf_1.json'), JSON.stringify({ workflowName: 'score-issue' }))
})
afterEach(() => rmSync(projects, { recursive: true, force: true }))

const record = {
	run: 'squid-x.1',
	createdAt: '2026-10-15T10:00:00Z',
	steps: [
		{ id: 'squid-x.1.review', closedAt: '2026-10-15T10:30:00Z' },
		{ id: 'squid-x.1.requirements', closedAt: '2026-10-15T10:10:00Z' },
		{ id: 'squid-x.1.score', closedAt: null },
	],
	actors: [ACTOR, ACTOR, 'Quang Le', 'Quang Le/claude-deadbeef'],
}

describe('trace-run', () => {
	it('maps an agent actor to its session by the last 8 hex digits', () => {
		expect(sessionSuffix(ACTOR)).toBe('a9c91d0b')
		expect(sessionSuffix('Quang Le/claude-a9c91d0b.agent-1a2d1b93')).toBe('a9c91d0b')
		expect(sessionSuffix('Quang Le')).toBeNull()
		expect(sessionSuffix('Quang Le/claude-../../etc')).toBeNull()
		expect(findSessions(projects, 'a9c91d0b').map((s) => s.session)).toEqual([SESSION])
	})

	it('counts each request once, with the effort of the request that preceded it', () => {
		const rs = requestsOf([
			req('t0', 'm', 'low'),
			res('t1', 'a', 'm', usage(1, 2), null),
			res('t2', 'a', 'm', usage(1, 50)),
			res('t3', 'a', 'm', usage(1, 2), null),
		])
		// The end is the latest entry, though that entry's usage is not kept.
		expect(rs).toEqual([{ id: 'a', ts: 't1', end: 't3', model: 'm', effort: 'low', usage: usage(1, 50), final: true }])
		// Without a stop entry (a subagent's response), the last entry written stands in for the end.
		expect(requestsOf([res('t1', 'd', 'm', usage(1, 2), null), res('t2', 'd', 'm', usage(1, 3), null)])[0]).toMatchObject({ ts: 't1', end: 't2' })
		expect(requestsOf([res('t1', 'b', 'm', usage(1, 2))])[0].effort).toBe('unknown')
		// Older transcripts have no api-request entries; the response carries its own effort.
		expect(requestsOf([{ ...res('t1', 'c', 'm', usage(1, 2)), effort: 'high' }])[0].effort).toBe('high')
	})

	it('puts each request in the first step closed at or after it, per agent, model and effort', () => {
		const t = trace(record, { projectsDir: projects, now: new Date('2026-10-15T12:00:00Z') })
		expect(t.steps.map((s) => s.step)).toEqual(['squid-x.1.requirements', 'squid-x.1.review'])
		const [requirements, review] = t.steps
		expect(requirements.agents).toEqual([
			{
				actor: ACTOR,
				kind: 'main',
				label: 'main',
				model: 'claude-opus-5-5',
				effort: 'medium',
				requests: 1,
				tokens: { input: 10, output: 300, cache_read: 5, cache_write: 7, cache_write_1h: 0, output_unknown: 0 },
				first: '2026-10-15T10:01:01Z',
				last: '2026-10-15T10:01:01Z',
				end: '2026-10-15T10:01:02Z',
				active_ms: 1000,
			},
		])
		expect(review.agents.map((a) => [a.kind, a.label, a.model, a.effort, a.requests])).toEqual([
			['main', 'main', 'claude-opus-5-5', 'high', 1],
			['subagent', expect.stringMatching(/^general-purpose: Review the diff .*…$/), 'claude-opus-5-5', 'medium', 1],
			['workflow', 'score-issue:judge', 'claude-fable-5-1', 'unknown', 1],
		])
		expect(review.agents[1].label.length).toBeLessThanOrEqual(80)
		// A subagent's response has no final usage: its output is unknown, not counted as the placeholder.
		expect(review.agents[1].tokens).toMatchObject({ input: 100, output: 0, output_unknown: 1 })
		expect(t.outside_requests).toBe(2)
		expect(t.open_steps).toEqual(['squid-x.1.score'])
		// Totals sum their agents' active time: the main thread's 1s and the subagent's single entry (0s).
		expect(t.totals.find((x) => x.model === 'claude-opus-5-5' && x.effort === 'medium')).toMatchObject({ requests: 2, active_ms: 1000 })
		expect(t.version).toBe(2)
		expect(t.timing).toMatchObject({ elapsed_ms: 30 * 60_000, human_wait_ms: 0, gates: [] })
		expect(t.timing.steps.map((s) => [s.step, s.start_from, s.elapsed_ms])).toEqual([
			['squid-x.1.requirements', 'created', 10 * 60_000],
			['squid-x.1.review', 'previous close', 20 * 60_000],
		])
	})

	it("times an agent from its first request to the end of its last, within a step", () => {
		const sub = join(projects, '-Users-quang-Projects-squi', SESSION, 'subagents')
		jsonl(join(sub, 'agent-a1.jsonl'), [
			req('2026-10-15T10:21:00Z', 'claude-opus-5-5', 'medium'),
			res('2026-10-15T10:21:01Z', 's1', 'claude-opus-5-5', usage(100, 8), null),
			req('2026-10-15T10:23:59Z', 'claude-opus-5-5', 'medium'),
			res('2026-10-15T10:24:00Z', 's2', 'claude-opus-5-5', usage(100, 8), null),
			res('2026-10-15T10:24:05Z', 's2', 'claude-opus-5-5', usage(100, 9), null),
		])
		const t = trace(record, { projectsDir: projects })
		const agent = t.steps.find((s) => s.step === 'squid-x.1.review').agents.find((a) => a.kind === 'subagent')
		expect(agent).toMatchObject({ requests: 2, first: '2026-10-15T10:21:01Z', last: '2026-10-15T10:24:00Z', end: '2026-10-15T10:24:05Z' })
		expect(agent.active_ms).toBe(Date.parse('2026-10-15T10:24:05Z') - Date.parse('2026-10-15T10:21:01Z'))
		expect(t.totals.find((x) => x.model === 'claude-opus-5-5' && x.effort === 'medium').active_ms).toBe(1000 + agent.active_ms)
	})

	it('lists agent actors without transcripts here as missing, and ignores people', () => {
		const t = trace(record, { projectsDir: projects })
		expect(t.missing).toEqual(['Quang Le/claude-deadbeef'])
		// A session's subagent actor is the same missing session.
		expect(trace({ ...record, actors: [...record.actors, 'Quang Le/claude-deadbeef.agent-7'] }, { projectsDir: projects }).missing).toEqual(['Quang Le/claude-deadbeef'])
		expect(t.sessions).toEqual([{ actor: ACTOR, session: SESSION }])
		expect(trace({ ...record, actors: ['Quang Le'] }, { projectsDir: join(projects, 'nope') }).steps).toEqual([])
	})

	it('summarizes who did what per step, with totals and what could not be traced', () => {
		const text = summarize(trace(record, { projectsDir: projects }))
		expect(text).toContain('not on this machine: Quang Le/claude-deadbeef')
		expect(text).toContain('open steps not traced: score')
		expect(text).toContain('- requirements (elapsed 10m 00s): main (claude-opus-5-5, medium, 1 req, 1s)')
		expect(text).toContain('score-issue:judge (claude-fable-5-1, unknown, 1 req, 0s)')
		expect(text).toMatch(/- claude-opus-5-5, medium: 2 req, 1s, in \d+ \(cache read 5\), out 300 \+ 1 req unknown/)
		expect(text).toMatch(/^Time: agents .* \(.*approximate\), human wait .*, elapsed .*idle gaps/m)
		expect(text).toContain('Time: agents 1s (first to last request per agent and step, summed; approximate), human wait 0s, elapsed 30m 00s')
		expect(text).not.toContain(SECRET)
	})

	it('counts a request copied into a resumed session once, for the session that made it', () => {
		const dir = join(projects, '-Users-quang-Projects-squi')
		const resumed = '11111111-2222-3333-4444-5555deadbeef'
		jsonl(join(dir, `${resumed}.jsonl`), [
			req('2026-10-15T10:01:00Z', 'claude-opus-5-5', 'medium'),
			res('2026-10-15T10:01:02Z', 'r1', 'claude-opus-5-5', usage(10, 300, 5, 7)), // copied from the parent
			req('2026-10-15T10:25:00Z', 'claude-opus-5-5', 'low'),
			res('2026-10-15T10:25:01Z', 'n1', 'claude-opus-5-5', usage(1, 1)),
		])
		const t = trace({ ...record, actors: ['Quang Le/claude-deadbeef', ACTOR] }, { projectsDir: projects })
		const requirements = t.steps.find((s) => s.step === 'squid-x.1.requirements')
		expect(requirements.agents.map((a) => [a.actor, a.requests])).toEqual([[ACTOR, 1]])
		const review = t.steps.find((s) => s.step === 'squid-x.1.review')
		expect(review.agents.find((a) => a.effort === 'low').actor).toBe('Quang Le/claude-deadbeef')
		expect(t.missing).toEqual([])
	})

	it('gives requests a fork copied to the session that made them, though both start at the same time', () => {
		const dir = join(projects, '-Users-quang-Projects-squi')
		const fork = '99999999-2222-3333-4444-5555feedf00d'
		jsonl(join(dir, `${fork}.jsonl`), [
			res('2026-10-15T09:59:01Z', 'r0', 'claude-opus-5-5', usage(1, 1)), // the parent's first request, copied
			res('2026-10-15T10:01:02Z', 'r1', 'claude-opus-5-5', usage(10, 300, 5, 7)), // copied
		])
		// The fork's actor comes first in the bd history, and the parent has more requests by the fork point.
		const t = trace({ ...record, actors: ['Quang Le/claude-feedf00d', ACTOR] }, { projectsDir: projects })
		const requirements = t.steps.find((s) => s.step === 'squid-x.1.requirements')
		expect(requirements.agents.map((a) => [a.actor, a.requests])).toEqual([[ACTOR, 1]])
	})

	it('gives the shared requests to the session created first, though its fork grew larger', () => {
		const dir = join(projects, '-Users-quang-Projects-squi')
		const fork = '99999999-2222-3333-4444-5555feedf00d'
		jsonl(join(dir, `${fork}.jsonl`), [
			res('2026-10-15T09:59:01Z', 'r0', 'claude-opus-5-5', usage(1, 1)), // copied from the parent
			res('2026-10-15T10:01:02Z', 'r1', 'claude-opus-5-5', usage(10, 300, 5, 7)), // copied
			...['f1', 'f2', 'f3', 'f4', 'f5'].map((id, i) => res(`2026-10-15T10:0${i + 2}:00Z`, id, 'claude-opus-5-5', usage(1, 1))),
		])
		const born = (file) => (file.includes(fork) ? 2000 : 1000)
		const step = (t) => t.steps.find((s) => s.step === 'squid-x.1.requirements').agents
		const t = trace({ ...record, actors: ['Quang Le/claude-feedf00d', ACTOR] }, { projectsDir: projects, birthOf: born })
		expect(step(t).map((a) => [a.actor, a.requests])).toEqual([
			[ACTOR, 1],
			['Quang Le/claude-feedf00d', 5],
		])
		// Without birth times, the larger session wins the tie.
		const u = trace({ ...record, actors: ['Quang Le/claude-feedf00d', ACTOR] }, { projectsDir: projects, birthOf: () => 0 })
		expect(step(u).map((a) => [a.actor, a.requests])).toEqual([['Quang Le/claude-feedf00d', 6]])
	})

	it('puts a request made at the exact close time in the step that closed', () => {
		const t = trace(
			{ ...record, createdAt: '2026-10-15T10:00:00.000Z', steps: [{ id: 'squid-x.1.a', closedAt: '2026-10-15T10:01:01Z' }, { id: 'squid-x.1.b', closedAt: '2026-10-15T10:30:00.000Z' }] },
			{ projectsDir: projects },
		)
		expect(t.steps.map((s) => [s.step, s.agents.reduce((n, a) => n + a.requests, 0)])).toEqual([
			['squid-x.1.a', 1],
			['squid-x.1.b', 3],
		])
	})

	it('reads a v1 trace without times in its summary', () => {
		const t = trace(record, { projectsDir: projects })
		for (const s of t.steps)
			for (const a of s.agents) {
				delete a.end
				delete a.active_ms
			}
		expect(summarize({ ...t, timing: undefined })).toContain('- requirements (elapsed –): main (claude-opus-5-5, medium, 1 req, 0s)')
	})

	it('never copies transcript content into the result', () => {
		expect(JSON.stringify(trace(record, { projectsDir: projects }))).not.toContain(SECRET)
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

	it('has no elapsed time while nothing is closed, and reads records without the new step fields', () => {
		expect(timingOf({ createdAt: at('10:00'), steps: [step('r.a', null)] })).toEqual({ elapsed_ms: null, human_wait_ms: 0, steps: [], gates: [] })
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
			{ issue_id: 'squid-x.1', op: 'created', ts: '2026-10-15T10:00:00.000Z', actor: 'Quang Le/claude-a9c91d0b' },
		],
		'squid-x.1.requirements': [
			{ issue_id: 'squid-x.1.requirements', op: 'closed', ts: '2026-10-15T10:05:00.000Z', actor: 'Quang Le/claude-a9c91d0b' },
		],
		'squid-x.1.review': [
			{ issue_id: 'squid-x.1.review', op: 'closed', ts: '2026-10-15T10:10:00.000Z', actor: 'Quang Le/claude-a9c91d0b.agent-1' },
			{ issue_id: 'squid-x.1.review', op: 'reopened', ts: '2026-10-15T10:11:00.000Z', actor: 'Quang Le' },
		],
		'squid-x.1.review.1': [{ issue_id: 'squid-x.1.review.1', op: 'closed', ts: '2026-10-15T10:09:00.000Z', actor: 'Quang Le/claude-0badc0de' }],
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
		expect(new Set(r.actors)).toEqual(new Set(['Quang Le/claude-a9c91d0b', 'Quang Le/claude-a9c91d0b.agent-1', 'Quang Le', 'Quang Le/claude-0badc0de']))
	})

	it('makes an issue without steps its own only step', () => {
		expect(readRecord('squid-x.1', fakeBd([], 'open').bd).steps).toEqual([{ id: 'squid-x.1', closedAt: null, startedAt: null, type: null, gate: null }])
	})

	it('refuses anything but a bd issue id', () => {
		expect(() => readRecord('squid-x.1; rm -rf /', fakeBd([]).bd)).toThrow('not a bd issue id')
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
		const r = cli(['squid-x.1', '--root', '/repo', '--projects', projects, '--actor', 'Quang Le/claude-a9c91d0b', '--write', '--summary'])
		expect(r.code).toBe(0)
		expect(r.out).toContain('- review (elapsed 30m 00s): main (claude-opus-5-5, medium, 1 req, 1s)')
		const update = readFileSync(join(bin, 'calls'), 'utf8').split('\n').find((l) => l.includes(' update '))
		expect(update).toMatch(/^-C \/repo update squid-x\.1 --set-metadata work=\{.*\} --actor Quang Le\/claude-a9c91d0b$/)
		expect(update).not.toContain(SECRET)
	})

	it('reports a failure in one line, not a stack', () => {
		const r = cli(['squid-x.1; rm -rf /', '--projects', projects])
		expect(r.code).toBe(1)
		expect(r.err).toBe('trace-run: not a bd issue id: squid-x.1; rm -rf /\n')
	})

	it('still prints the trace when the write fails, and says why', () => {
		const r = cli(['squid-x.1', '--projects', projects, '--write', '--summary'], { FAIL_WRITE: '1' })
		expect(r.code).toBe(1)
		expect(r.out).toContain('Work trace: 1 session(s)')
		expect(r.err).toContain('could not store the work metadata on squid-x.1: server unreachable')
	})
})
