import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import { claudeRequestsOf, claudeSources, claudeSuffix, findClaudeSessions, harnessOf, logDirs, summarize, trace } from './trace-run.mjs'

// Claude Code transcripts as trace-run reads them, next to trace-run.spec.mjs's Copilot session logs.
const SESSION = '6f26e090-4089-4a32-bdd2-c49ba9c91d0b'
const ACTOR = 'Quang Le/claude-a9c91d0b'
const SECRET = 'bd_live_SECRET_TOKEN_must_not_leak'
const MODEL = 'claude-opus-5-5'

const req = (ts, effort = 'medium') => ({ type: 'api-request', timestamp: ts, params: { model: MODEL, output_config: { effort } } })
const res = (ts, id, usage, { stop = 'end_turn', model = MODEL, content = [{ type: 'text', text: SECRET }] } = {}) => ({
	type: 'assistant',
	timestamp: ts,
	requestId: id,
	message: { model, stop_reason: stop, usage, content },
})
const usage = (input, output, cache_read = 0, cache_write = 0, cache_write_1h = 0) => ({
	input_tokens: input,
	output_tokens: output,
	cache_read_input_tokens: cache_read,
	cache_creation_input_tokens: cache_write,
	cache_creation: { ephemeral_1h_input_tokens: cache_write_1h },
})
const toolUse = (id, name) => ({ type: 'tool_use', id, name, input: { command: SECRET } })
const toolResult = (ts, id) => ({ type: 'user', timestamp: ts, message: { content: [{ type: 'tool_result', tool_use_id: id, content: SECRET }] } })
const jsonl = (file, entries) => writeFileSync(file, entries.map((e) => JSON.stringify(e)).join('\n') + '\n{not json\n')

let projects
let dir
beforeEach(() => {
	projects = mkdtempSync(join(tmpdir(), 'trace-run-claude-'))
	dir = join(projects, '-Users-quang-Projects-squi')
	const sub = join(dir, SESSION, 'subagents')
	const wf = join(sub, 'workflows', 'wf_1')
	mkdirSync(wf, { recursive: true })
	mkdirSync(join(dir, SESSION, 'workflows'), { recursive: true })
	jsonl(join(dir, `${SESSION}.jsonl`), [
		{ type: 'user', timestamp: '2026-10-15T10:00:00Z', message: { content: SECRET } },
		req('2026-10-15T09:59:00Z'),
		res('2026-10-15T09:59:01Z', 'r0', usage(1, 1)), // before the run: left out
		req('2026-10-15T10:01:00Z'),
		// One request written as two entries: counted once, with the final entry's usage.
		res('2026-10-15T10:01:01Z', 'r1', usage(10, 3), { stop: null }),
		res('2026-10-15T10:01:02Z', 'r1', usage(10, 300, 5, 7, 7)),
		req('2026-10-15T10:20:00Z', 'high'),
		res('2026-10-15T10:20:01Z', 'r2', usage(20, 40)),
		res('2026-10-15T10:20:02Z', 'r3', usage(0, 0), { model: '<synthetic>' }), // not a model request
		req('2026-10-15T11:00:00Z'),
		res('2026-10-15T11:00:01Z', 'r4', usage(1, 1)), // after the last close: left out
	])
	jsonl(join(sub, 'agent-a1.jsonl'), [req('2026-10-15T10:21:00Z'), res('2026-10-15T10:21:01Z', 's1', usage(100, 8), { stop: null })])
	writeFileSync(join(sub, 'agent-a1.meta.json'), JSON.stringify({ agentType: 'general-purpose', description: 'Review the diff '.repeat(10) }))
	jsonl(join(wf, 'agent-w1.jsonl'), [res('2026-10-15T10:22:00Z', 'w1', usage(50, 9), { model: 'claude-fable-5-1' })])
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

describe('trace-run on Claude Code transcripts', () => {
	it('maps a Claude Code actor to its session by the last 8 hex digits', () => {
		expect(claudeSuffix(ACTOR)).toBe('a9c91d0b')
		expect(claudeSuffix('Quang Le/claude-a9c91d0b.agent-a1b2')).toBe('a9c91d0b')
		// A BD_SESSION sub-actor, and a subagent of one.
		expect(claudeSuffix('Quang Le/claude-a9c91d0b.worker_1')).toBe('a9c91d0b')
		expect(claudeSuffix('Quang Le/claude-a9c91d0b.Worker-1.agent-x')).toBe('a9c91d0b')
		expect(claudeSuffix('Quang Le/copilot-a9c91d0b')).toBeNull()
		expect(claudeSuffix('Quang Le/claude-../../etc')).toBeNull()
		expect(harnessOf(ACTOR)).toEqual({ harness: 'claude', suffix: 'a9c91d0b' })
		expect(harnessOf('Quang Le/copilot-a9c91d0b.w1')).toEqual({ harness: 'copilot', suffix: 'a9c91d0b' })
		expect(harnessOf('Quang Le')).toBeNull()
		expect(findClaudeSessions(projects, 'a9c91d0b')).toEqual([{ dir, session: SESSION }])
		expect(findClaudeSessions(projects, 'deadbeef')).toEqual([])
	})

	it('reads each request once, from the api-request before it, with its effort and final usage', () => {
		const rs = claudeRequestsOf([
			req('2026-10-15T10:01:00Z', 'high'),
			res('2026-10-15T10:01:03Z', 'r1', usage(10, 3), { stop: null }),
			res('2026-10-15T10:01:04Z', 'r1', usage(10, 300, 5, 7, 7)),
			res('2026-10-15T10:02:00Z', 'r2', usage(1, 9), { stop: null }), // no api-request entry, never final
		])
		expect(rs).toEqual([
			{
				id: 'r1',
				harness: 'claude',
				ts: '2026-10-15T10:01:00Z',
				end: '2026-10-15T10:01:04Z',
				model: MODEL,
				effort: 'high',
				tools: [],
				tokens: { input: 10, output: 300, cache_read: 5, cache_write: 7, cache_write_1h: 7, output_unknown: 0 },
			},
			{
				id: 'r2',
				harness: 'claude',
				ts: '2026-10-15T10:02:00Z',
				end: '2026-10-15T10:02:00Z',
				model: MODEL,
				effort: 'high',
				tools: [],
				tokens: { input: 1, output: 0, cache_read: 0, cache_write: 0, cache_write_1h: 0, output_unknown: 1 },
			},
		])
	})

	it('gives a request the tools it called, tool_use to tool_result, but not waits on a person or another agent', () => {
		const ms = (t) => Date.parse(t)
		const [r] = claudeRequestsOf([
			req('2026-10-15T10:00:00Z'),
			res('2026-10-15T10:00:01Z', 'r1', usage(1, 1), { stop: 'tool_use', content: [toolUse('b1', 'Bash'), toolUse('q1', 'AskUserQuestion'), toolUse('g1', 'Agent')] }),
			toolResult('2026-10-15T10:00:31Z', 'b1'),
			toolResult('2026-10-15T10:05:00Z', 'q1'),
			toolResult('2026-10-15T10:06:00Z', 'g1'),
			toolResult('2026-10-15T10:07:00Z', 'nope'),
		])
		expect(r.tools).toEqual([[ms('2026-10-15T10:00:01Z'), ms('2026-10-15T10:00:31Z')]])
	})

	it("labels the main thread, a subagent by its type and description, and a workflow agent by its workflow and label", () => {
		const labels = claudeSources(dir, SESSION).map((s) => [s.kind, s.label])
		expect(labels[0]).toEqual(['main', 'main'])
		expect(labels[1][0]).toBe('subagent')
		expect(labels[1][1]).toMatch(/^general-purpose: Review the diff .*…$/)
		expect(labels[1][1].length).toBeLessThanOrEqual(80)
		expect(labels[2]).toEqual(['workflow', 'score-issue:judge'])
	})

	it('puts each request in the first step closed at or after it, per agent, model and effort, without credits', () => {
		const t = trace(record, { projectsDir: projects })
		expect(t.steps.map((s) => s.step)).toEqual(['squid-x.1.requirements', 'squid-x.1.review'])
		const [requirements, review] = t.steps
		expect(requirements.agents).toEqual([
			{
				actor: ACTOR,
				harness: 'claude',
				kind: 'main',
				label: 'main',
				model: MODEL,
				effort: 'medium',
				requests: 1,
				tokens: { input: 10, output: 300, cache_read: 5, cache_write: 7, cache_write_1h: 7, output_unknown: 0 },
				first: '2026-10-15T10:01:00Z',
				last: '2026-10-15T10:01:00Z',
				end: '2026-10-15T10:01:02Z',
				active_ms: 2_000,
			},
		])
		expect(review.agents.map((a) => [a.kind, a.model, a.effort, a.requests])).toEqual([
			['main', MODEL, 'high', 1],
			['subagent', MODEL, 'medium', 1],
			['workflow', 'claude-fable-5-1', 'unknown', 1], // its transcript has no api-request entry
		])
		expect(t.outside_requests).toBe(2)
		expect(t.missing).toEqual(['Quang Le/claude-deadbeef'])
		expect(t.sessions).toEqual([{ actor: ACTOR, session: SESSION, harness: 'claude' }])
		expect(t.totals.every((x) => x.harness === 'claude' && x.tokens.nano_aiu === undefined)).toBe(true)
	})

	it("leaves out the time a main thread sat idle while its background workflow ran", () => {
		// The bd-sync-8gdf shape: start a workflow, end the turn, wake on its notification twelve minutes later.
		jsonl(join(dir, `${SESSION}.jsonl`), [
			req('2026-10-15T10:01:00Z'),
			res('2026-10-15T10:01:03Z', 'm1', usage(1, 1), { stop: 'tool_use', content: [toolUse('wf', 'Workflow')] }),
			toolResult('2026-10-15T10:01:04Z', 'wf'),
			req('2026-10-15T10:01:04Z'),
			res('2026-10-15T10:01:08Z', 'm2', usage(1, 1)),
			{ type: 'system', subtype: 'turn_duration', timestamp: '2026-10-15T10:01:08Z' },
			{ type: 'user', timestamp: '2026-10-15T10:13:00Z', message: { content: '<task-notification>' } },
			req('2026-10-15T10:13:00Z'),
			res('2026-10-15T10:13:05Z', 'm3', usage(1, 1), { stop: 'tool_use', content: [toolUse('b', 'Bash')] }),
			toolResult('2026-10-15T10:13:25Z', 'b'),
			req('2026-10-15T10:13:25Z'),
			res('2026-10-15T10:13:30Z', 'm4', usage(1, 1)),
		])
		const t = trace({ ...record, steps: [{ id: 'squid-x.1.implement', closedAt: '2026-10-15T10:30:00Z' }] }, { projectsDir: projects })
		// 3 s + its 1 s tool + 4 s before the twelve idle minutes, 5 s + a 20 s build + 5 s after them.
		const [main] = t.steps[0].agents.filter((a) => a.kind === 'main')
		expect([main.requests, main.active_ms]).toEqual([4, 8_000 + 30_000])
	})

	it('counts a request copied into a resumed session once, for the session that made it', () => {
		jsonl(join(dir, '11111111-2222-3333-4444-5555deadbeef.jsonl'), [
			req('2026-10-15T10:01:00Z'),
			res('2026-10-15T10:01:02Z', 'r1', usage(10, 300, 5, 7)), // copied from the parent
			req('2026-10-15T10:25:00Z', 'low'),
			res('2026-10-15T10:25:01Z', 'n1', usage(1, 1)),
		])
		const t = trace({ ...record, actors: ['Quang Le/claude-deadbeef', ACTOR] }, { projectsDir: projects })
		expect(t.steps.find((s) => s.step === 'squid-x.1.requirements').agents.map((a) => [a.actor, a.requests])).toEqual([[ACTOR, 1]])
		expect(t.steps.find((s) => s.step === 'squid-x.1.review').agents.find((a) => a.effort === 'low').actor).toBe('Quang Le/claude-deadbeef')
		expect(t.missing).toEqual([])
	})

	it('gives the shared requests to the session created first, though its fork grew larger', () => {
		const fork = '99999999-2222-3333-4444-5555feedf00d'
		jsonl(join(dir, `${fork}.jsonl`), [
			res('2026-10-15T09:59:01Z', 'r0', usage(1, 1)), // copied from the parent
			res('2026-10-15T10:01:02Z', 'r1', usage(10, 300, 5, 7)), // copied
			...['f1', 'f2', 'f3', 'f4', 'f5'].map((id, i) => res(`2026-10-15T10:0${i + 2}:00Z`, id, usage(1, 1))),
		])
		const step = (t) => t.steps.find((s) => s.step === 'squid-x.1.requirements').agents
		const actors = ['Quang Le/claude-feedf00d', ACTOR]
		// The parent's copy of r1 starts at its api-request, before the fork's: the parent made it.
		expect(step(trace({ ...record, actors }, { projectsDir: projects, birthOf: (f) => (f.includes(fork) ? 2000 : 1000) })).map((a) => [a.actor, a.requests])).toEqual([
			[ACTOR, 1],
			['Quang Le/claude-feedf00d', 5],
		])
	})

	it('traces a run worked by both harnesses, keeping their totals apart', () => {
		const sessions = mkdtempSync(join(tmpdir(), 'trace-run-copilot-'))
		try {
			const copilot = '11111111-2222-3333-4444-5555c0ffee00'
			mkdirSync(join(sessions, copilot))
			const record_ = { type: 'session.usage_record', timestamp: '2026-10-15T10:21:01Z', data: { usage: { model: MODEL, inputTokens: 3, outputTokens: 1, duration: 1000, reasoningEffort: 'medium', apiCallId: 'c1', copilotUsage: { totalNanoAiu: 1e9 } } } }
			jsonl(join(sessions, copilot, 'events.jsonl'), [record_])
			const t = trace({ ...record, actors: [ACTOR, 'Quang Le/copilot-c0ffee00'] }, { projectsDir: projects, sessionsDir: sessions })
			expect(t.sessions.map((s) => s.harness)).toEqual(['claude', 'copilot'])
			const medium = t.totals.filter((x) => x.model === MODEL && x.effort === 'medium')
			expect(medium.map((x) => [x.harness, x.requests]).toSorted()).toEqual([
				['claude', 2],
				['copilot', 1],
			])
			const text = summarize(t)
			expect(text).toContain(`- copilot ${MODEL}, medium: 1 req, 1s, in 3 (cache read 0), out 1, 1.0 credits`)
			expect(text).toMatch(new RegExp(`- claude ${MODEL}, medium: 2 req, .* \\+ 1 req unknown$`, 'm'))
		} finally {
			rmSync(sessions, { recursive: true, force: true })
		}
	})

	it('finds each harness under its own directory, from the environment or the options', () => {
		const none = () => undefined
		expect(logDirs(none, { COPILOT_HOME: '/c', CLAUDE_CONFIG_DIR: '/k' })).toEqual({ sessionsDir: join('/c', 'session-state'), projectsDir: join('/k', 'projects') })
		expect(logDirs((n) => ({ '--sessions': '/s', '--projects': '/p' })[n], {})).toEqual({ sessionsDir: '/s', projectsDir: '/p' })
	})

	it('never copies transcript content into the result', () => {
		expect(JSON.stringify(trace(record, { projectsDir: projects }))).not.toContain(SECRET)
	})
})
