import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import { execFileSync, spawnSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { aggregate, coderOf, controllerSessions, costOf, joinRuns, overlaps, plannerOf, PRICES, render, roleOf, sessionReader, untracedWhy } from './calibrate.mjs'
import { ROLE_PREFIXES } from './reviewer-catch.mjs'

// credits: the AI credits a request cost; left out, a trace stored without them.
const tokens = (input, output, cache_read = 0, cache_write = 0, credits) => ({ input, output, cache_read, cache_write, ...(credits == null ? {} : { nano_aiu: credits * 1e9 }) })
const agent = (kind, label, requests, t, model = 'claude-opus-5.5', effort = 'medium', times = {}) => ({ kind, label, model, effort, requests, tokens: t, ...times })
const work = (...agents) => ({ steps: [{ step: 's', agents }] })
// An agent's times: first request at `from`, last request at `last`, which ended at `end` (minutes:seconds past 01:00).
const at = (from, last, end) => ({ first: `2026-10-15T01:${from}Z`, last: `2026-10-15T01:${last}Z`, ...(end ? { end: `2026-10-15T01:${end}Z` } : {}) })
const timing = (elapsed_ms, human_wait_ms, steps = []) => ({ elapsed_ms, human_wait_ms, steps, gates: [] })
const run = (id, metadata, extra = {}) => ({
	id,
	title: id,
	status: 'closed',
	created_at: extra.created_at ?? '2026-10-15T00:00:00Z',
	metadata: { playbook: { name: 'change', role: 'run', vars: { tier: extra.tier ?? 'small', task: id } }, ...metadata },
})

describe('roleOf', () => {
	it.each([
		[{ kind: 'main', label: 'main' }, 'main'],
		[{ kind: 'workflow', label: 'plan-implement-review:coder:implement' }, 'coder'],
		[{ kind: 'workflow', label: 'implement-review:review:code:r0@strong' }, 'reviewer'],
		[{ kind: 'workflow', label: 'implement-review:validate:r0:TabBar.svelte' }, 'validator'],
		[{ kind: 'workflow', label: 'plan-implement-review:planner:triage:r1' }, 'planner'],
		[{ kind: 'workflow', label: 'implement-review:heartbeat' }, 'mechanical'],
		[{ kind: 'workflow', label: 'plan-implement-review:claim@sonnet' }, 'mechanical'],
		[{ kind: 'workflow', label: 'plan-implement-review:gate:impl@sonnet' }, 'mechanical'],
		[{ kind: 'workflow', label: 'score-issue:judge' }, 'judge'],
		[{ kind: 'workflow', label: 'score-issue:trace' }, 'mechanical'],
		[{ kind: 'subagent', label: 'general-purpose: Independent review of scoring trace' }, 'reviewer'],
		[{ kind: 'subagent', label: 'Explore: find the tokens file' }, 'other'],
		// A description's role prefix, after Claude Code's agentType or Copilot's agentName.
		[{ kind: 'subagent', label: 'general-purpose: coder: fit-all' }, 'coder'],
		[{ kind: 'subagent', label: 'general-purpose: Reviewer: review r1 bd-x.1' }, 'reviewer'],
		[{ kind: 'subagent', label: 'Explore: research: find the tokens file' }, 'research'],
		[{ kind: 'subagent', label: 'summary: digest the journal' }, 'summary'],
		[{ kind: 'subagent', label: 'general-purpose: mechanical: run the tests' }, 'mechanical'],
		[{ kind: 'subagent', label: 'Plan: planner: z' }, 'planner'],
		[{ kind: 'subagent', label: 'plugin:agent: coder: a' }, 'coder'],
		[{ kind: 'subagent', label: 'task: mechanical: run cargo test' }, 'mechanical'],
		[{ kind: 'subagent', label: 'explore: research: where is the lease' }, 'research'],
		[{ kind: 'subagent', label: 'code-review: reviewer: diff' }, 'reviewer'],
		// A role word anywhere else is not a prefix.
		[{ kind: 'subagent', label: 'general-purpose: Fix the planner: bug' }, 'other'],
		[{ kind: 'subagent', label: 'general-purpose: Fix: coder: x' }, 'other'],
		[{ kind: 'subagent', label: 'Fix: coder: x' }, 'other'],
		// A workflow label keeps its workflow role, whatever its agent's description.
		[{ kind: 'workflow', label: 'plan-implement-review:coder: fix' }, 'coder'],
	])('%o is a %s', (a, role) => expect(roleOf(a)).toBe(role))
	// Every shared role prefix (reviewer-catch.mjs's ROLE_PREFIXES) is classified as its role.
	it.each(ROLE_PREFIXES)('%s: y is that role', (r) => expect(roleOf({ kind: 'subagent', label: `${r}: y` })).toBe(r))
})

describe('coderOf', () => {
	it('sums requests per model and effort among workflow coder agents, ignoring other roles', () => {
		const w = work(
			agent('workflow', 'plan-implement-review:coder:S1', 10, tokens(1, 1), 'claude-sonnet-5.5', 'medium'),
			agent('workflow', 'plan-implement-review:implement', 8, tokens(1, 1), 'claude-opus-5.5', 'high'),
			agent('workflow', 'plan-implement-review:coder:S2', 5, tokens(1, 1), 'claude-opus-5.5', 'high'),
			agent('workflow', 'plan-implement-review:review:code:r0', 50, tokens(1, 1), 'claude-opus-5.5', 'high'),
			agent('main', 'main', 99, tokens(1, 1), 'claude-opus-5.5', 'high'),
		)
		expect(coderOf(w)).toEqual({ model: 'claude-opus-5.5', effort: 'high', requests: 13 })
	})

	it('prefers workflow coder agents over a `coder:` subagent with more requests', () => {
		const w = work(
			agent('workflow', 'plan-implement-review:coder:S1', 6, tokens(1, 1), 'claude-sonnet-5.5', 'medium'),
			agent('subagent', 'general-purpose: coder: close bd-x.1', 40, tokens(1, 1), 'claude-opus-5.5', 'high'),
		)
		expect(coderOf(w)).toEqual({ model: 'claude-sonnet-5.5', effort: 'medium', requests: 6 })
	})

	it('falls back to `coder:` subagents when there is no workflow coder agent', () => {
		const w = work(
			agent('subagent', 'general-purpose: coder: a', 4, tokens(1, 1), 'claude-opus-5-5', 'high'),
			agent('subagent', 'general-purpose: coder: b', 3, tokens(1, 1), 'claude-sonnet-5.5', 'medium'),
			agent('main', 'main', 50, tokens(1, 1), 'claude-sonnet-5.5', 'medium'),
			agent('workflow', 'plan-implement-review:review:code:r0', 30, tokens(1, 1), 'claude-sonnet-5.5', 'medium'),
		)
		expect(coderOf(w)).toEqual({ model: 'claude-opus-5.5', effort: 'high', requests: 4 })
	})

	it('counts one model named both ways (Claude Code and Copilot ids) as one coder', () => {
		const w = work(
			agent('workflow', 'plan-implement-review:implement', 5, tokens(1, 1), 'claude-opus-5-5', 'high'),
			agent('workflow', 'plan-implement-review:coder:S1', 4, tokens(1, 1), 'claude-opus-5.5', 'high'),
			agent('workflow', 'plan-implement-review:coder:S2', 7, tokens(1, 1), 'claude-sonnet-5.5', 'high'),
		)
		expect(coderOf(w)).toEqual({ model: 'claude-opus-5.5', effort: 'high', requests: 9 })
	})

	it('is null without a coder agent or a trace', () => {
		expect(coderOf(work(agent('main', 'main', 9, tokens(1, 1)), agent('subagent', 'Explore: find it', 3, tokens(1, 1))))).toBeNull()
		expect(coderOf(null)).toBeNull()
	})
})

describe('plannerOf', () => {
	it('sums requests per model and effort among workflow planner, critic and triage agents, ignoring other roles and subagents', () => {
		// Counting the planner: subagent, the validator or the coder would make high win.
		const w = work(
			agent('workflow', 'plan-implement-review:planner:draft', 3, tokens(1, 1), 'claude-opus-5.5', 'medium'),
			agent('workflow', 'plan-implement-review:planner:critic:0', 2, tokens(1, 1), 'claude-opus-5-5', 'medium'),
			agent('workflow', 'plan-implement-review:planner:triage:r0', 4, tokens(1, 1), 'claude-opus-5.5', 'high'),
			agent('subagent', 'general-purpose: planner: plan bd-x', 2, tokens(1, 1), 'claude-opus-5.5', 'high'),
			agent('workflow', 'plan-implement-review:validate:r0:F1', 50, tokens(1, 1), 'claude-opus-5.5', 'high'),
			agent('workflow', 'plan-implement-review:coder:S1', 20, tokens(1, 1), 'claude-opus-5.5', 'high'),
		)
		expect(plannerOf(w)).toEqual({ model: 'claude-opus-5.5', effort: 'medium', requests: 5 })
	})

	it('prefers workflow planner agents over a `planner:` subagent with more requests', () => {
		const w = work(
			agent('workflow', 'plan-implement-review:planner:draft', 2, tokens(1, 1), 'claude-opus-5.5', 'high'),
			agent('subagent', 'general-purpose: planner: plan bd-x', 5, tokens(1, 1), 'claude-opus-5.5', 'medium'),
		)
		expect(plannerOf(w)).toEqual({ model: 'claude-opus-5.5', effort: 'high', requests: 2 })
	})

	it('falls back to `planner:` subagents when there is no workflow planner agent', () => {
		const w = work(
			agent('subagent', 'general-purpose: planner: plan bd-x', 3, tokens(1, 1), 'claude-opus-5.5', 'high'),
			agent('subagent', 'Plan: planner: estimate bd-x', 2, tokens(1, 1), 'claude-opus-5.5', 'medium'),
			agent('workflow', 'plan-implement-review:coder:S1', 30, tokens(1, 1), 'claude-opus-5.5', 'medium'),
			agent('workflow', 'plan-implement-review:validate:r0:F1', 30, tokens(1, 1), 'claude-opus-5.5', 'medium'),
		)
		expect(plannerOf(w)).toEqual({ model: 'claude-opus-5.5', effort: 'high', requests: 3 })
	})

	it('is null without a planner agent or a trace', () => {
		expect(plannerOf(work(agent('main', 'main', 9, tokens(1, 1)), agent('subagent', 'Explore: find it', 3, tokens(1, 1))))).toBeNull()
		expect(plannerOf(null)).toBeNull()
	})
})

describe('costOf', () => {
	it('prices tokens from the AI credits they cost, at $0.01 a credit', () => {
		expect(costOf(tokens(1e6, 1e6, 1e6, 1e6, 400))).toBeCloseTo(4)
		expect(costOf({ nano_aiu: 13_074_213_820_000 })).toBeCloseTo(130.74)
	})

	it('has no cost for a trace stored without credits', () => {
		expect(costOf(tokens(1, 1))).toBeNull()
		expect(costOf(undefined)).toBeNull()
	})

	const table = {
		cache_write_multiplier: 1.25,
		cache_write_1h_multiplier: 2,
		models: { 'claude-opus-5-5': { input: 4, output: 20, cache_read: 0.2 } },
	}
	it("prices a Claude Code agent's tokens at the model's list prices, cache writes by their TTL", () => {
		// 1M input $4, 1M output $20, 1M cache read $0.20, 1M 5-minute writes $5 and 1M 1-hour writes $8.
		const t = { input: 1e6, output: 1e6, cache_read: 1e6, cache_write: 2e6, cache_write_1h: 1e6, output_unknown: 3 }
		expect(costOf(t, 'claude-opus-5-5', table)).toBeCloseTo(37.2)
		// Without a split by TTL, every write is a 5-minute one.
		expect(costOf({ input: 0, output: 0, cache_read: 0, cache_write: 1e6 }, 'claude-opus-5-5', table)).toBeCloseTo(5)
	})

	it('prefers logged credits, and leaves a model the table lacks unpriced', () => {
		expect(costOf(tokens(1e6, 1e6, 0, 0, 100), 'claude-opus-5-5', table)).toBeCloseTo(1)
		expect(costOf(tokens(1e6, 1e6), 'claude-opus-5.5', table)).toBeNull()
		expect(costOf(tokens(1e6, 1e6), undefined, table)).toBeNull()
	})

	it('ships list prices for the current Claude models', () => {
		for (const m of ['claude-fable-5-1', 'claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5'])
			expect(Object.keys(PRICES.models[m]).toSorted()).toEqual(['cache_read', 'input', 'output'])
		expect(PRICES).toMatchObject({ cache_write_multiplier: 1.25, cache_write_1h_multiplier: 2 })
		expect(typeof PRICES.source).toBe('string')
	})

	it('totals list-priced Claude Code agents with credit-priced ones, counting unrecorded output apart', () => {
		const claude = { ...agent('main', 'main', 4, { input: 1e6, output: 0, cache_read: 0, cache_write: 0, cache_write_1h: 0, output_unknown: 2 }, 'claude-opus-5-5') }
		const copilot = agent('workflow', 'plan-implement-review:review:code:r0', 2, tokens(1, 1, 0, 0, 100))
		const unknown = agent('subagent', 'Explore: x', 1, { input: 5, output: 0 }, 'claude-mystery-9')
		const agg = aggregate([{ id: 'r', work: work(claude, copilot, unknown) }], { ...table, source: 'test table', note: 'test note' })
		expect(agg.roles.find((x) => x.role === 'main')).toMatchObject({ cost: 4, outputUnknown: 2, unpriced: 0 })
		expect(agg.roles.find((x) => x.role === 'other')).toMatchObject({ cost: 0, unpriced: 1, outputUnknown: 0 })
		const md = render([{ id: 'r', tier: 'small', findings: { serious: 0, minor: 0, followUps: [] }, traced: 'stored', work: work(claude, copilot, unknown) }], agg, { ...table, source: 'test table', note: 'test note' })
		expect(md).toContain('$5.00 + 2 req output unknown + 1 req unpriced')
		expect(md).toContain('notional list prices (test table)')
		expect(md).toContain('test note')
	})
})

describe('untracedWhy', () => {
	it('says why a trace can\'t stand for the run, or null', () => {
		expect(untracedWhy({ sessions: [], missing: ['a/copilot-1'], steps: [] })).toBe('sessions not on this machine')
		expect(untracedWhy({ sessions: [], missing: [], steps: [] })).toBe('no agent sessions')
		expect(untracedWhy({ sessions: [{}], missing: [], steps: [], outside_requests: 7 })).toBe("no requests inside the run's step windows (7 outside)")
		expect(untracedWhy({ sessions: [{}], missing: [], steps: [{}] })).toBeNull()
	})
})

describe('joinRuns', () => {
	const issues = [
		run('squid-b.1', { complexity_estimate: { score: 2 }, score_judge: { complexity: 3, overall: 4 }, work: work(agent('main', 'main', 4, tokens(100, 10))) }, { created_at: '2026-10-15T02:00:00Z' }),
		run('squid-a.1', { score: { overall: 3, complexity: 4 }, score_judge: { complexity: 3, overall: 3 } }, { tier: 'standard', created_at: '2026-10-15T01:00:00Z' }),
		{ id: 'squid-a.1.requirements', status: 'closed', issue_type: 'task', closed_at: '2026-10-15T01:10:00Z' },
		{ id: 'squid-a.1.implement', status: 'closed', issue_type: 'task', started_at: '2026-10-15T01:05:00Z', closed_at: '2026-10-15T01:40:00Z' },
		{
			id: 'squid-a.1.gate-design',
			status: 'closed',
			issue_type: 'gate',
			closed_at: '2026-10-15T01:50:00Z',
			metadata: { gate: { type: 'human', armed_at: '2026-10-15T01:45:00Z' } },
		},
		{ id: 'squid-a.1.review', status: 'open', issue_type: 'task', started_at: '2026-10-15T01:55:00Z' },
		{ id: 'squid-a.1.review.1', labels: ['severity:serious'], status: 'closed', close_reason: 'fixed in abc' },
		{ id: 'squid-a.1.review.2', labels: ['severity:minor'], status: 'closed', close_reason: 'fixed' },
		{ id: 'squid-a.1.review.3', labels: ['severity:serious'], status: 'closed', close_reason: 'duplicate of squid-a.1.review.1' },
		{ id: 'squid-f1', status: 'open' },
		{ id: 'squid-f2', status: 'closed', close_reason: 'duplicate of squid-f1' },
		{ id: 'squid-other', metadata: { playbook: { name: 'other', role: 'run' } } },
	]
	const traced = []
	const rows = joinRuns(issues, {
		followUpsOf: (step) => (step === 'squid-a.1.review' ? ['squid-f1', 'squid-f2'] : []),
		traceOf: (id) => (traced.push(id), { work: null, why: 'sessions not on this machine' }),
	})

	it('lists change playbook runs in creation order', () => {
		expect(rows.map((r) => r.id)).toEqual(['squid-a.1', 'squid-b.1'])
	})

	it('tells a judge draft accepted as the score from one a person confirmed', () => {
		const [row] = joinRuns([run('squid-c.1', { score: { overall: 4, complexity: 3, by: 'judge' }, score_judge: { complexity: 3, overall: 4 } })], {
			followUpsOf: () => [],
			traceOf: () => ({ work: null, why: 'none' }),
		})
		expect(row).toMatchObject({ overall: 4, overallFrom: 'accepted', confirmedComplexity: 3 })
	})

	it('prefers the confirmed score and complexity, and marks a judge draft', () => {
		expect(rows[0]).toMatchObject({ tier: 'standard', overall: 3, overallFrom: 'person', judged: 3, confirmedComplexity: 4 })
		expect(rows[1]).toMatchObject({ estimate: 2, judged: 3, overall: 4, overallFrom: 'judge' })
	})

	it('counts review findings and follow-ups without duplicates', () => {
		expect(rows[0].findings).toEqual({ serious: 1, minor: 1, followUps: 1 })
	})

	it('leaves follow-ups unknown when they could not be read, and marks the backfill of an open run partial', () => {
		const [row] = joinRuns([{ ...run('squid-c.1', {}), status: 'open' }], {
			followUpsOf: () => null,
			traceOf: () => ({ work: work(agent('main', 'main', 1, tokens(1, 1))), why: null }),
		})
		expect(row).toMatchObject({ findings: { followUps: null }, traced: 'partial' })
	})

	it('times the run from its direct children, never from nested findings', () => {
		expect(rows[0].timing).toEqual({
			start: '2026-10-15T01:00:00Z',
			start_from: 'created',
			elapsed_ms: 50 * 60_000,
			human_wait_ms: 5 * 60_000,
			steps: [
				{ step: 'squid-a.1.requirements', start: '2026-10-15T01:00:00Z', start_from: 'created', closed_at: '2026-10-15T01:10:00Z', elapsed_ms: 10 * 60_000 },
				{ step: 'squid-a.1.implement', start: '2026-10-15T01:05:00Z', start_from: 'claim', closed_at: '2026-10-15T01:40:00Z', elapsed_ms: 35 * 60_000 },
			],
			gates: [{ gate: 'squid-a.1.gate-design', type: 'human', armed_at: '2026-10-15T01:45:00Z', resolved_at: '2026-10-15T01:50:00Z', wait_ms: 5 * 60_000 }],
		})
		// A run without steps is its own only step; it has no close time here, so no elapsed time.
		expect(rows[1].timing).toMatchObject({ elapsed_ms: null, human_wait_ms: 0, steps: [], gates: [] })
	})

	it('uses a stored trace and traces only runs without one', () => {
		expect(rows[1].traced).toBe('stored')
		expect(rows[0]).toMatchObject({ traced: null, untraced: 'sessions not on this machine' })
		expect(traced).toEqual(['squid-a.1'])
	})

	it("carries the rubric version of the score it reports, and the estimate's", () => {
		const byId = Object.fromEntries(
			joinRuns(
				[
					// Confirmed under v3 though the judge used v2: the confirmed score's version.
					run('bd-v.1', { score: { overall: 4, complexity: 3, rubric: 3 }, score_judge: { overall: 3, complexity: 3, rubric: 2 }, complexity_estimate: { score: 3, rubric: 3 } }),
					// A draft only: the judge's version.
					run('bd-v.2', { score_judge: { overall: 3, complexity: 2, rubric: 2 }, complexity_estimate: { score: 2, rubric: 1 } }),
					// Accepted: the judge's draft copied into score, version and all.
					run('bd-v.3', { score: { overall: 4, complexity: 2, rubric: 3, by: 'judge' }, score_judge: { overall: 4, complexity: 2, rubric: 3 } }),
					// No version anywhere, or not an integer.
					run('bd-v.4', { score_judge: { overall: 3, complexity: 2 }, complexity_estimate: { score: 2 } }),
					run('bd-v.5', { score_judge: { overall: 3, complexity: 2, rubric: '2' }, complexity_estimate: { score: 2, rubric: 2.5 } }),
					// A score without a version is unknown, with no fallback to the judge's.
					run('bd-v.6', { score: { overall: 4, complexity: 3 }, score_judge: { overall: 3, complexity: 3, rubric: 2 } }),
				],
				{ followUpsOf: () => [], traceOf: () => ({ work: null, why: 'no agent sessions' }) },
			).map((r) => [r.id, [r.rubric, r.estimateRubric, r.overallFrom]]),
		)
		expect(byId).toEqual({
			'bd-v.1': [3, 3, 'person'],
			'bd-v.2': [2, 1, 'judge'],
			'bd-v.3': [3, null, 'accepted'],
			'bd-v.4': [null, null, 'judge'],
			'bd-v.5': [null, null, 'judge'],
			'bd-v.6': [null, null, 'person'],
		})
	})

	it("puts each run's coder and exploration marker on its row", () => {
		expect(rows.map((r) => [r.coder, r.exploration])).toEqual([
			[null, null],
			[null, null],
		])
		const exploration = { coder: 'sonnet/medium', rule: 'sha1-0-3' }
		const [row] = joinRuns([run('bd-e.1', { exploration, work: work(agent('workflow', 'plan-implement-review:coder:S1', 6, tokens(1, 1), 'claude-sonnet-5.5', 'medium')) })], {
			followUpsOf: () => [],
			traceOf: () => ({ work: null, why: 'unused' }),
		})
		expect(row).toMatchObject({ exploration, coder: { model: 'claude-sonnet-5.5', effort: 'medium', requests: 6 } })
		expect(JSON.parse(JSON.stringify(row)).exploration).toEqual(exploration)
	})

	it("puts each run's planner on its row", () => {
		expect(rows.map((r) => r.planner)).toEqual([null, null])
		const exploration = { planner: 'opus/medium', plannerRule: 'sha1-2-0-3' }
		const [row] = joinRuns([run('bd-p.1', { exploration, work: work(agent('workflow', 'plan-implement-review:planner:draft', 7, tokens(1, 1), 'claude-opus-5-5', 'medium')) })], {
			followUpsOf: () => [],
			traceOf: () => ({ work: null, why: 'unused' }),
		})
		const planner = { model: 'claude-opus-5.5', effort: 'medium', requests: 7 }
		expect(row).toMatchObject({ exploration, planner })
		expect(JSON.parse(JSON.stringify(row)).planner).toEqual(planner)
	})
})

// A run judged complexity 2, as aggregate reads it.
const scoredRow = (id, overall, serious, w, extra = {}) => ({ id, tier: 'small', estimate: 2, judged: 2, confirmedComplexity: null, overall, findings: { serious, minor: 0, followUps: 0 }, work: w, timing: null, ...extra })

describe('aggregate and render', () => {
	const rows = [
		{
			id: 'r1',
			tier: 'small',
			estimate: 2,
			judged: 3,
			confirmedComplexity: null,
			overall: 4,
			findings: { serious: 0, minor: 1, followUps: 0 },
			// A v1 trace: no end time, so last minus first.
			work: { steps: [{ step: 'r1.implement', agents: [agent('main', 'main', 4, tokens(0, 100, 400_000), undefined, undefined, at('00:00', '02:00'))] }] },
			timing: timing(30 * 60_000, 0, [
				{ step: 'r1.requirements', elapsed_ms: 5 * 60_000 },
				{ step: 'r1.implement', elapsed_ms: 20 * 60_000 },
			]),
		},
		{
			id: 'r2',
			tier: 'small',
			estimate: 2,
			judged: 2,
			confirmedComplexity: 2,
			overall: 4,
			findings: { serious: 0, minor: 0, followUps: 0 },
			work: null,
			timing: timing(60 * 60_000, 10 * 60_000, [{ step: 'r2.requirements', elapsed_ms: 15 * 60_000 }]),
		},
		{
			id: 'r3',
			tier: 'standard',
			estimate: 3,
			judged: 3,
			confirmedComplexity: 4,
			overall: 3,
			findings: { serious: 2, minor: 0, followUps: 1 },
			work: work(
				agent('workflow', 'wf:review:code', 10, tokens(1_000_000, 0, 0, 0, 400), 'claude-opus-5.5', 'high', at('00:00', '03:00', '04:30')),
				agent('subagent', 'Explore: x', 2, tokens(10, 0), 'claude-mystery-1', 'low', { ...at('00:00', '00:30', '01:00'), active_ms: 45_000 }),
			),
			timing: null,
		},
	]
	const agg = aggregate(rows)

	it('measures the estimate gap against the confirmed complexity, else the judged one', () => {
		// Rows without rubric versions count under unknown.
		expect(agg.gap).toMatchObject({
			mixed: 0,
			byRubric: [{ rubric: null, runs: 3, distribution: [[0, 1], [1, 2]], byTier: { small: { runs: 2, mean: 0.5 }, standard: { runs: 1, mean: 1 } } }],
		})
		expect(agg.gap.byRubric[0].mean).toBeCloseTo(2 / 3)
	})

	it('groups scores by complexity band', () => {
		expect(agg.bands).toEqual([
			{ rubric: null, complexity: 2, runs: 1, overall: 4, serious: 0 },
			{ rubric: null, complexity: 3, runs: 1, overall: 4, serious: 0 },
			{ rubric: null, complexity: 4, runs: 1, overall: 3, serious: 2 },
		])
	})

	it('puts runs without a coder agent apart from untraced ones in the score by coder', () => {
		expect(agg.coders).toEqual([
			{ rubric: null, complexity: 2, coder: 'untraced', model: null, effort: null, runs: 1, overall: 4, serious: 0, exploration: 0 },
			{ rubric: null, complexity: 3, coder: 'no coder agent', model: null, effort: null, runs: 1, overall: 4, serious: 0, exploration: 0 },
			{ rubric: null, complexity: 4, coder: 'no coder agent', model: null, effort: null, runs: 1, overall: 3, serious: 2, exploration: 0 },
		])
	})

	it('scores each complexity band by coder, counting exploration runs', () => {
		const explored = [
			scoredRow('e1', 4, 0, work(agent('workflow', 'plan-implement-review:coder:S1', 5, tokens(1, 1, 0, 0, 10), 'claude-sonnet-5.5', 'medium')), { exploration: { coder: 'sonnet/medium', rule: 'sha1-0-3' } }),
			scoredRow('e2', 3, 1, work(agent('subagent', 'general-purpose: coder: x', 5, tokens(1, 1), 'claude-opus-5-5', 'high'))),
			scoredRow('e3', 5, 0, null),
		]
		const a = aggregate(explored)
		expect(a.coders).toEqual([
			{ rubric: null, complexity: 2, coder: 'claude-opus-5.5/high', model: 'claude-opus-5.5', effort: 'high', runs: 1, overall: 3, serious: 1, exploration: 0 },
			{ rubric: null, complexity: 2, coder: 'claude-sonnet-5.5/medium', model: 'claude-sonnet-5.5', effort: 'medium', runs: 1, overall: 4, serious: 0, exploration: 1 },
			{ rubric: null, complexity: 2, coder: 'untraced', model: null, effort: null, runs: 1, overall: 5, serious: 0, exploration: 0 },
		])
		const md = render(explored, a)
		expect(md).toContain('## Score by coder')
		expect(md).toContain('| unknown | 2 | claude-sonnet-5.5/medium | 1 | 4 | 0 | 1 |')
		expect(md).toContain('exploration counts runs marked by the coder exploration quota')
		expect(md).toContain('or among its \`coder:\` subagents when it has none')
	})

	it('puts runs without a planner agent apart from untraced ones in the score by planner', () => {
		expect(agg.planners).toEqual([
			{ rubric: null, complexity: 2, planner: 'untraced', model: null, effort: null, runs: 1, overall: 4, serious: 0, plannerCost: null, exploration: 0 },
			{ rubric: null, complexity: 3, planner: 'no planner agent', model: null, effort: null, runs: 1, overall: 4, serious: 0, plannerCost: 0, exploration: 0 },
			{ rubric: null, complexity: 4, planner: 'no planner agent', model: null, effort: null, runs: 1, overall: 3, serious: 2, plannerCost: 0, exploration: 0 },
		])
	})

	it('scores each complexity band by planner, with the planner cost per run, counting planner exploration runs', () => {
		const explored = [
			scoredRow(
				'p1',
				4,
				0,
				work(
					agent('workflow', 'plan-implement-review:planner:draft', 5, tokens(1, 1, 0, 0, 400), 'claude-opus-5.5', 'medium'),
					agent('workflow', 'plan-implement-review:validate:r0:F1', 9, tokens(1, 1, 0, 0, 900), 'claude-opus-5.5', 'high'),
					agent('subagent', 'general-purpose: planner: estimate p1', 1, tokens(1, 1, 0, 0, 100), 'claude-opus-5.5', 'high'),
				),
				{ exploration: { planner: 'opus/medium', plannerRule: 'sha1-2-0-3' } },
			),
			scoredRow('p2', 3, 1, work(agent('subagent', 'general-purpose: planner: x', 5, tokens(1, 1, 0, 0, 200), 'claude-opus-5-5', 'high'))),
			scoredRow('p3', 5, 0, null),
		]
		const a = aggregate(explored)
		// p1's cost is its draft ($4) and its pre-step subagent ($1), not its validator.
		expect(a.planners).toEqual([
			{ rubric: null, complexity: 2, planner: 'claude-opus-5.5/high', model: 'claude-opus-5.5', effort: 'high', runs: 1, overall: 3, serious: 1, plannerCost: 2, exploration: 0 },
			{ rubric: null, complexity: 2, planner: 'claude-opus-5.5/medium', model: 'claude-opus-5.5', effort: 'medium', runs: 1, overall: 4, serious: 0, plannerCost: 5, exploration: 1 },
			{ rubric: null, complexity: 2, planner: 'untraced', model: null, effort: null, runs: 1, overall: 5, serious: 0, plannerCost: null, exploration: 0 },
		])
		const md = render(explored, a)
		expect(md).toContain('## Score by planner')
		expect(md).toContain('| unknown | 2 | claude-opus-5.5/medium | 1 | 4 | 0 | $5.00 | 1 |')
		expect(md).toContain('exploration counts runs marked by the planner effort exploration')
	})

	it('counts coder and planner exploration from their own keys of one exploration value', () => {
		const w = work(
			agent('workflow', 'plan-implement-review:coder:S1', 5, tokens(1, 1), 'claude-sonnet-5.5', 'medium'),
			agent('workflow', 'plan-implement-review:planner:draft', 3, tokens(1, 1), 'claude-opus-5.5', 'medium'),
		)
		const plannerOnly = { planner: 'opus/medium', plannerRule: 'sha1-2-0-3' }
		const coderOnly = { coder: 'sonnet/medium', rule: 'sha1-0-3' }
		const a = aggregate([
			scoredRow('x1', 4, 0, w, { exploration: plannerOnly }),
			scoredRow('x2', 4, 0, w, { exploration: coderOnly }),
			scoredRow('x3', 4, 0, w, { exploration: { ...coderOnly, ...plannerOnly } }),
		])
		expect(a.coders[0].exploration).toBe(2)
		expect(a.planners[0].exploration).toBe(2)
		expect(aggregate([scoredRow('x1', 4, 0, w, { exploration: plannerOnly })]).coders[0].exploration).toBe(0)
	})

	it('splits the score by coder by rubric version, so one band under v2 and v3 stays apart', () => {
		const opus = work(agent('subagent', 'general-purpose: coder: x', 5, tokens(1, 1), 'claude-opus-5-5', 'high'))
		const a = aggregate([scoredRow('v2', 4, 0, opus, { rubric: 2 }), scoredRow('v3', 3, 1, opus, { rubric: 3 })])
		expect(a.coders.map((x) => [x.rubric, x.complexity, x.coder, x.runs])).toEqual([
			[2, 2, 'claude-opus-5.5/high', 1],
			[3, 2, 'claude-opus-5.5/high', 1],
		])
		expect(render([], a)).toContain('| v3 | 2 | claude-opus-5.5/high | 1 | 3 | 1 | 0 |')
	})

	it('costs roles by model and effort, keeping traces without credits apart', () => {
		const reviewer = agg.roles.find((x) => x.role === 'reviewer')
		expect(reviewer).toMatchObject({ model: 'claude-opus-5.5', effort: 'high', runs: 1, requests: 10 })
		expect(reviewer.cost).toBeCloseTo(4)
		expect(agg.roles.find((x) => x.role === 'other')).toMatchObject({ unpriced: 2, cost: 0 })
		expect(agg.mainPerRequest).toEqual([{ id: 'r1', requests: 4, perRequest: 100_000 }])
	})

	it('merges one model named both ways (Claude Code and Copilot ids) into one role row, priced on the raw id', () => {
		const table = { cache_write_multiplier: 1.25, cache_write_1h_multiplier: 2, models: { 'claude-opus-5-5': { input: 4, output: 20, cache_read: 0.2 } }, source: 'test table', note: 'test note' }
		const ta = { input: 1e6, output: 0, cache_read: 0, cache_write: 0, output_unknown: 2 }
		const tb = tokens(1, 1, 0, 0, 100)
		const a = agent('workflow', 'wf:review:code', 3, ta, 'claude-opus-5-5', 'high', at('00:00', '01:00', '02:00'))
		const b = agent('workflow', 'wf:review:code', 2, tb, 'claude-opus-5.5', 'high', at('00:00', '00:30', '01:00'))
		const wa = work(a)
		const wb = work(b)
		const agg2 = aggregate([{ id: 'a', work: wa }, { id: 'b', work: wb }], table)
		const rows2 = agg2.roles.filter((x) => x.role === 'reviewer')
		expect(rows2.length).toBe(1)
		expect(rows2[0]).toMatchObject({ model: 'claude-opus-5.5', effort: 'high', runs: 2, requests: 5, unpriced: 0, outputUnknown: 2, activeMs: 3 * 60_000 })
		expect(rows2[0].cost).toBeCloseTo(costOf(ta, 'claude-opus-5-5', table) + costOf(tb, 'claude-opus-5.5', table))
		expect(rows2[0].cost).toBeCloseTo(5)
		expect(agg2.runCosts.a.cost).toBeCloseTo(4)
		expect(agg2.runCosts.b.cost).toBeCloseTo(1)
		const md = render([{ id: 'a', tier: 'small', findings: { serious: 0, minor: 0, followUps: [] }, traced: 'stored', work: wa }, { id: 'b', tier: 'small', findings: { serious: 0, minor: 0, followUps: [] }, traced: 'stored', work: wb }], agg2, table)
		expect(md).toContain('| reviewer | claude-opus-5.5 | high | 2 | 5 |')
		expect(/\| reviewer \| claude-opus-5-5 \|/.test(md)).toBe(false)
	})

	it('times roles by model and effort: first request to the end of the last, else (v1) the last request, or a stored span', () => {
		expect(agg.roles.find((x) => x.role === 'reviewer').activeMs).toBe(4.5 * 60_000)
		expect(agg.roles.find((x) => x.role === 'main').activeMs).toBe(2 * 60_000)
		expect(agg.roles.find((x) => x.role === 'other').activeMs).toBe(45_000)
	})

	it('times each run: agent time when traced, human wait and elapsed time from bd', () => {
		expect(agg.runTimes).toEqual({
			r1: { agentMs: 2 * 60_000, humanWaitMs: 0, elapsedMs: 30 * 60_000 },
			r2: { agentMs: null, humanWaitMs: 10 * 60_000, elapsedMs: 60 * 60_000 },
			r3: { agentMs: 4.5 * 60_000 + 45_000, humanWaitMs: null, elapsedMs: null },
		})
	})

	it('puts cost and time by complexity band, cost and agent time over traced runs only', () => {
		const [two, three, four] = agg.bandTimes
		expect(two).toEqual({ rubric: null, complexity: 2, runs: 1, traced: 0, cost: null, agentMs: null, humanWaitMs: 10 * 60_000, elapsedMs: 60 * 60_000 })
		expect(three).toMatchObject({ complexity: 3, runs: 1, traced: 1, agentMs: 2 * 60_000, humanWaitMs: 0, elapsedMs: 30 * 60_000 })
		expect(three.cost).toBeCloseTo(agg.runCosts.r1.cost)
		expect(four).toMatchObject({ complexity: 4, runs: 1, traced: 1, agentMs: 4.5 * 60_000 + 45_000, humanWaitMs: null, elapsedMs: null })
	})

	it('times steps across runs: mean elapsed over runs that closed it, mean agent time over traced ones', () => {
		expect(agg.stepTimes).toEqual([
			// r1 is traced but made no request in requirements: 0, not left out.
			{ step: 'requirements', runs: 2, elapsedMs: 10 * 60_000, traced: 1, agentMs: 0 },
			{ step: 'implement', runs: 1, elapsedMs: 20 * 60_000, traced: 1, agentMs: 2 * 60_000 },
		])
	})

	it('leaves out of a step\'s agent time the runs whose trace was written while that step was open', () => {
		// The trace is stored at the score step, so score was still open then; bd shows it closed now.
		const row = {
			id: 'r4',
			tier: 'small',
			estimate: 2,
			judged: 2,
			confirmedComplexity: null,
			overall: 4,
			findings: { serious: 0, minor: 0, followUps: 0 },
			work: { open_steps: ['r4.score'], steps: [{ step: 'r4.requirements', agents: [agent('main', 'main', 1, tokens(10, 1), undefined, undefined, at('00:00', '00:00', '00:30'))] }] },
			timing: timing(20 * 60_000, 0, [
				{ step: 'r4.requirements', elapsed_ms: 10 * 60_000 },
				{ step: 'r4.score', elapsed_ms: 5 * 60_000 },
			]),
		}
		expect(aggregate([row]).stepTimes).toEqual([
			{ step: 'requirements', runs: 1, elapsedMs: 10 * 60_000, traced: 1, agentMs: 30_000 },
			{ step: 'score', runs: 1, elapsedMs: 5 * 60_000, traced: 0, agentMs: null },
		])
	})

	it('renders every section, with costs from credits and drafts marked', () => {
		const md = render([{ ...rows[0], overallFrom: 'judge', traced: 'stored' }, { ...rows[1], overallFrom: 'person', traced: null, untraced: 'no agent sessions' }], agg)
		for (const heading of [
			'## Runs',
			'## Complexity: estimate vs judged',
			'## Score by complexity',
			'## Score by coder',
			'## Score by planner',
			'## Cost and time by complexity',
			'## Time by step',
			'## Cost and time by role, model and effort',
			'## Main-thread context per request',
			'## Controller sessions',
		])
			expect(md).toContain(heading)
		expect(md.indexOf('## Main-thread context per request')).toBeLessThan(md.indexOf('## Controller sessions'))
		expect(md).toContain('No traced session on this machine.')
		expect(md.indexOf('## Score by coder')).toBeLessThan(md.indexOf('## Score by planner'))
		expect(md.indexOf('## Score by planner')).toBeLessThan(md.indexOf('## Cost and time by complexity'))
		expect(md).toContain('Costs are Copilot AI credits as USD (1 credit = $0.01)')
		expect(md).toContain('| r1 | small | 2 | 3 | 1 | 4 (draft) | – |')
		expect(md).toContain('| unknown | 2 | 1 | 4 | 0 |')
		expect(md).toContain('Mixed versions: 0 runs')
		expect(md).toContain('none: no agent sessions')
		expect(md).toContain('+ 2 req unpriced')
	})

	it('renders times next to costs, and says which time is primary', () => {
		const md = render([{ ...rows[0], overallFrom: 'judge', traced: 'stored' }, { ...rows[1], overallFrom: 'person', traced: null, untraced: 'no agent sessions' }], agg)
		expect(md).toContain('| follow-ups | cost | agent time | human wait | elapsed | trace |')
		expect(md).toMatch(/\| r1 \|(.*\|){9} 2m 00s \| 0s \| 30m 00s \| stored \|/)
		expect(md).toMatch(/\| r2 \|(.*\|){9} – \| 10m 00s \| 1h 00m \|/)
		expect(md).toContain('| requests | cost | agent time |')
		expect(md).toContain('| 2 | 1 | 0 | – | – | 10m 00s | 1h 00m |')
		expect(md).toContain('| requirements | 2 | 10m 00s | 1 | 0s |')
		expect(md).toContain('| implement | 1 | 20m 00s | 1 | 2m 00s |')
		for (const phrase of ['Agent time is the primary time figure', "A Copilot request's start is its record's time less its duration", 'waited on a person or on another agent is left out', 'includes idle gaps and is context only', 'Human wait (human gates, armed to resolved) is counted apart'])
			expect(md).toContain(phrase)
	})

	it('says when there is nothing to time', () => {
		const md = render([], aggregate([]))
		expect(md).toContain('No run has both an estimate and a judged complexity yet.')
		expect(md).toContain('No scored run has a complexity yet.')
		expect(md).toContain('No run has a complexity yet.')
		expect(md).toContain('No closed steps.')
		expect(md).toContain('No traced session on this machine.')
	})

	it('renders controller sessions, a missing one as not on this machine', () => {
		const controllers = [
			{
				harness: 'claude',
				session: 'sess-a',
				missing: false,
				first: '2026-10-01T10:00:00.000Z',
				last: '2026-10-01T12:30:00.000Z',
				requests: 40,
				cost: 1.5,
				unpriced: 1,
				outputUnknown: 0,
				perRequestByQuarter: [150000, null, 170000, null],
				runs: ['r1', 'r2'],
				finished: ['r2'],
			},
			{ harness: 'copilot', session: 'sess-b', missing: true, first: null, last: null, requests: null, cost: null, unpriced: 0, outputUnknown: 0, perRequestByQuarter: [null, null, null, null], runs: ['r3'], finished: [] },
		]
		const md = render([], { ...aggregate([]), controllers })
		expect(md).toContain('| session | harness | first | last | main requests | cost | Q1 | Q2 | Q3 | Q4 | runs | finished |')
		expect(md).toContain('| sess-a | claude | 2026-10-01 10:00 | 2026-10-01 12:30 | 40 | $1.50 + 1 req unpriced | 150k | – | 170k | – | r1, r2 | r2 |')
		expect(md).toContain('| sess-b | copilot | not on this machine | – | – | – | – | – | – | – | r3 | – |')
		expect(md).toContain('150k')
		expect(md).toContain('– |')
		expect(md).toContain('+ 1 req unpriced')
		expect(md).not.toContain('No traced session on this machine.')
		for (const phrase of ['whole main thread', 'subagent and workflow requests are left out', 'counted once', 'listed as not on this machine'])
			expect(md).toContain(phrase)
	})
})

// A run judged at `complexity` under rubric `rubric`, estimated at 2 under `estimateRubric`.
const vrow = (id, rubric, estimateRubric, complexity, extra = {}) => ({
	id,
	tier: 'small',
	estimate: 2,
	judged: complexity,
	confirmedComplexity: null,
	overall: 4,
	findings: { serious: 0, minor: 0, followUps: 0 },
	work: null,
	timing: timing(10 * 60_000, 0),
	rubric,
	estimateRubric,
	...extra,
})

describe('complexity tables per rubric version', () => {
	// Out of order on purpose: unknown and v3 first.
	const rows = [vrow('r-unknown', null, null, 3), vrow('r-v3', 3, 3, 3, { overall: 3 }), vrow('r-mixed', 3, 2, 3, { overall: 5, findings: { serious: 1, minor: 0, followUps: 0 } }), vrow('r-v2', 2, 2, 3)]
	const agg = aggregate(rows)

	it('splits score and cost/time bands by version, sorted v2, v3, unknown, with a mixed run under its judged version', () => {
		expect(agg.bands).toEqual([
			{ rubric: 2, complexity: 3, runs: 1, overall: 4, serious: 0 },
			{ rubric: 3, complexity: 3, runs: 2, overall: 4, serious: 1 },
			{ rubric: null, complexity: 3, runs: 1, overall: 4, serious: 0 },
		])
		expect(agg.bandTimes.map((x) => [x.rubric, x.complexity, x.runs])).toEqual([
			[2, 3, 1],
			[3, 3, 2],
			[null, 3, 1],
		])
	})

	it('sorts bands by version, then complexity', () => {
		const a = aggregate([vrow('a', 3, 3, 2), vrow('b', 2, 2, 4), vrow('c', null, null, 1), vrow('d', 2, 2, 2)])
		expect(a.bands.map((x) => [x.rubric, x.complexity])).toEqual([
			[2, 2],
			[2, 4],
			[3, 2],
			[null, 1],
		])
	})

	it("leaves a run whose estimate and judged versions differ out of every version's gap, and counts it as mixed", () => {
		expect(agg.gap.mixed).toBe(1)
		expect(agg.gap.byRubric.map((x) => [x.rubric, x.runs])).toEqual([
			[2, 1],
			[3, 1],
			[null, 1],
		])
	})

	it('counts an estimate of unknown version against a known judged version as mixed', () => {
		const a = aggregate([vrow('a', 2, null, 3), vrow('b', null, 2, 3)])
		expect(a.gap).toEqual({ mixed: 2, byRubric: [] })
		expect(a.bands.map((x) => x.rubric)).toEqual([2, null])
	})

	it("renders a leading rubric column, the run's versions and the mixed count", () => {
		const md = render(rows, agg)
		expect(md).toContain('| run | tier | estimate | complexity | gap | overall | rubric | serious |')
		expect(md).toContain('| r-mixed | small | 2 | 3 | 1 | 5 | v3 (estimate v2) |')
		expect(md).toContain('| r-v2 | small | 2 | 3 | 1 | 4 | v2 |')
		expect(md).toContain('| r-unknown | small | 2 | 3 | 1 | 4 | – |')
		expect(md).toContain('| rubric | runs | mean gap | distribution | by tier |')
		expect(md).toContain('| v2 | 1 | 1 | +1: 1 | small 1 over 1 |')
		expect(md).toContain('| unknown | 1 | 1 | +1: 1 | small 1 over 1 |')
		expect(md).toContain('Mixed versions: 1 run whose estimate and judged complexity used different rubric versions, counted in neither.')
		expect(md).toContain('| rubric | complexity | runs | mean overall | serious findings |')
		expect(md).toContain('| v3 | 3 | 2 | 4 | 1 |')
		expect(md).toContain('| rubric | complexity | runs | traced | mean cost (usd) | mean agent time | mean human wait | mean elapsed |')
		expect(md).toContain('| unknown | 3 | 1 | 0 | – | – | 0s | 10m 00s |')
		expect(md).toContain('Bands are per rubric version')
	})

	it('shows the mixed count even when no run has matching versions', () => {
		const md = render([], aggregate([vrow('a', 2, null, 3)]))
		expect(md).toContain('Mixed versions: 1 run whose')
		expect(md).not.toContain('| rubric | runs | mean gap |')
	})
})

// A traced run whose requests were made from active[0] to active[1] (by default its whole window).
const traced = (id, created, closed, session, requests, active = [created, closed]) => ({
	id,
	created,
	findings: { serious: 0, minor: 0, followUps: 0 },
	work: {
		sessions: [{ session }],
		steps: [{ step: `${id}.s`, closed_at: closed, agents: [{ ...agent('main', 'main', requests, tokens(1e6, 0, 0, 0, 400)), first: active[0], last: active[1], end: active[1] }] }],
	},
})

describe('overlaps', () => {
	const runs = [
		traced('nested', '2026-10-15T01:00:00Z', '2026-10-15T01:10:00Z', 's1', 5),
		traced('wide', '2026-10-15T01:00:00Z', '2026-10-15T01:20:00Z', 's1', 9),
		traced('other-session', '2026-10-15T01:05:00Z', '2026-10-15T01:15:00Z', 's2', 3),
		traced('later', '2026-10-15T02:00:00Z', '2026-10-15T02:10:00Z', 's1', 4),
	]

	it('groups runs that share a session and overlap in time, keeping the one with the most requests', () => {
		const o = overlaps(runs)
		expect(o.groups).toEqual([{ runs: ['nested', 'wide'], kept: 'wide', doubleCounted: false }])
		expect([...o.excluded]).toEqual(['nested'])
	})

	it('leaves out a run created a moment earlier whose requests all fall inside the kept window', () => {
		const o = overlaps([
			traced('early', '2026-10-15T01:00:00.000Z', '2026-10-15T01:10:00Z', 's1', 5, ['2026-10-15T01:00:04Z', '2026-10-15T01:09:00Z']),
			traced('kept', '2026-10-15T01:00:00.100Z', '2026-10-15T01:20:00Z', 's1', 9),
		])
		expect(o.groups).toEqual([{ runs: ['early', 'kept'], kept: 'kept', doubleCounted: false }])
		expect([...o.excluded]).toEqual(['early'])
	})

	it('keeps a run that only partly overlaps in the totals, and flags the double count', () => {
		const partial = [traced('a', '2026-10-15T01:00:00Z', '2026-10-15T01:30:00Z', 's1', 9), traced('b', '2026-10-15T01:20:00Z', '2026-10-15T02:00:00Z', 's1', 5)]
		const o = overlaps(partial)
		expect(o.groups).toEqual([{ runs: ['a', 'b'], kept: 'a', doubleCounted: true }])
		expect([...o.excluded]).toEqual([])
		expect(aggregate(partial).roles.find((x) => x.role === 'main').requests).toBe(14)
	})

	it('counts an overlap group once in the role totals, and says so', () => {
		const agg = aggregate(runs)
		// wide 20m + other-session 10m + later 10m; nested's 10m is inside wide's.
		expect(agg.roles.find((x) => x.role === 'main')).toMatchObject({ requests: 9 + 3 + 4, runs: 3, activeMs: 40 * 60_000 })
		expect(agg.runTimes.nested.agentMs).toBe(10 * 60_000)
		expect(agg.runCosts.nested.cost).toBeCloseTo(4)
		const md = render(runs.map((r) => Object.assign(structuredClone(r), { tier: 'small', traced: 'stored' })), agg)
		expect(md).toContain('| nested | small |')
		expect(md).toContain('stored, overlaps (left out of totals)')
		expect(md).toContain('nested + wide (totals use wide)')
		expect(md).toContain('A Copilot request with no logged credits')
	})
})

// A main-thread request at hh:mm on 2026-10-15, reading `read` tokens (input), with its own extras.
const mreq = (id, hhmm, read = 1000, extra = {}) => ({
	id,
	ts: `2026-10-15T${hhmm}:00Z`,
	end: `2026-10-15T${hhmm}:30Z`,
	model: 'claude-opus-5-5',
	tokens: { input: read, output: 10, cache_read: 0, cache_write: 0 },
	...extra,
})
// A run naming sessions [{ session, harness }], with one traced step closing at stepClose and a bd timing closing at close.
const csRun = (id, sessions, { status = 'closed', start = '2026-10-15T09:00:00Z', close, stepClose = '2026-10-15T10:30:00Z' } = {}) => ({
	id,
	status,
	created: start,
	work: { sessions: sessions.map((s) => ({ actor: `u/${s.harness ?? 'copilot'}-00000000`, harness: 'claude', ...s })), steps: [{ step: `${id}.s`, closed_at: stepClose, agents: [] }] },
	timing: close ? { start, elapsed_ms: Date.parse(close) - Date.parse(start), human_wait_ms: 0, steps: [], gates: [] } : undefined,
})
const stub = (logs) => (s) => logs.get(s.session) ?? null

describe('controllerSessions', () => {
	it('counts every main request of the session, far outside the run step windows', () => {
		const logs = new Map([['A', [mreq('r1', '02:00'), mreq('r2', '10:15'), mreq('r3', '20:00')]]])
		const [row] = controllerSessions([csRun('x', [{ session: 'A' }])], stub(logs))
		expect(row).toMatchObject({ harness: 'claude', session: 'A', missing: false, requests: 3, first: '2026-10-15T02:00:00Z', last: '2026-10-15T20:00:30Z', runs: ['x'] })
	})

	it('reads each quarter as the mean tokens per request, by position in time order', () => {
		const at8 = Array.from({ length: 8 }, (_, j) => mreq(`q${j}`, `1${j}:00`, (j + 1) * 100))
		const rows = (reqs) => controllerSessions([csRun('x', [{ session: 'A' }])], stub(new Map([['A', reqs]])))[0]
		// Shuffled input: quarters follow ts, not input order.
		expect(rows(at8.toReversed()).perRequestByQuarter).toEqual([150, 350, 550, 750])
		expect(rows([mreq('a', '10:00', 100), mreq('b', '11:00', 200), mreq('c', '12:00', 300)]).perRequestByQuarter).toEqual([100, 200, 300, null])
		expect(rows([mreq('a', '10:00', 100), mreq('b', '11:00', 300)]).perRequestByQuarter).toEqual([100, null, 300, null])
		expect(rows([mreq('a', '10:00', 101)]).perRequestByQuarter).toEqual([101, null, null, null])
		expect(rows([])).toMatchObject({ requests: 0, first: null, last: null, cost: 0, perRequestByQuarter: [null, null, null, null] })
		// Cache reads and writes count as read; a mean is rounded.
		const cached = mreq('a', '10:00', 0, { tokens: { input: 1, output: 9, cache_read: 2, cache_write: 4 } })
		expect(rows([cached, mreq('b', '10:00', 0)]).perRequestByQuarter).toEqual([7, null, 0, null])
	})

	it('prices each request, counting unpriced and output-unknown ones apart', () => {
		const priced = mreq('a', '10:00', 1000)
		const lacking = mreq('b', '10:05', 1000, { model: 'claude-unknown-9' })
		const unknownOut = mreq('c', '10:10', 1000, { tokens: { input: 1000, output: 0, cache_read: 0, cache_write: 0, output_unknown: 1 } })
		const [row] = controllerSessions([csRun('x', [{ session: 'A' }])], stub(new Map([['A', [priced, lacking, unknownOut]]])))
		expect(row.cost).toBeCloseTo(costOf(priced.tokens, priced.model) + costOf(unknownOut.tokens, unknownOut.model))
		expect(row).toMatchObject({ unpriced: 1, outputUnknown: 1, requests: 3 })
		const cop = mreq('p', '10:00', 1000, { model: 'claude-opus-5.5', tokens: { input: 1000, output: 1, cache_read: 0, cache_write: 0, nano_aiu: 3e9 }, owned: true })
		const [c] = controllerSessions([csRun('y', [{ session: 'C', harness: 'copilot' }])], stub(new Map([['C', [cop]]])))
		expect(c).toMatchObject({ harness: 'copilot', unpriced: 0 })
		expect(c.cost).toBeCloseTo(0.03)
	})

	it('counts a run handed off across two sessions as finished once, in the session that closed it', () => {
		const logs = new Map([
			['A', [mreq('a1', '10:00'), mreq('a2', '11:00')]],
			['B', [mreq('b1', '11:30'), mreq('b2', '12:30')]],
		])
		const rows = controllerSessions([csRun('x', [{ session: 'A' }, { session: 'B' }], { close: '2026-10-15T12:00:00Z' })], stub(logs))
		expect(rows.map((r) => [r.session, r.runs, r.finished])).toEqual([
			['A', ['x'], []],
			['B', ['x'], ['x']],
		])
		// Both spans hold the close: the session with the latest request before it finished the run.
		const both = new Map([
			['A', [mreq('a1', '10:00'), mreq('a2', '11:50'), mreq('a3', '13:00')]],
			['B', [mreq('b1', '09:00'), mreq('b2', '11:40'), mreq('b3', '12:10'), mreq('b4', '14:00')]],
		])
		const rs = controllerSessions([csRun('x', [{ session: 'A' }, { session: 'B' }], { close: '2026-10-15T12:00:00Z' })], stub(both))
		expect(rs.map((r) => [r.session, r.finished])).toEqual([
			['B', []],
			['A', ['x']],
		])
		// Without timing, the traced steps' last close decides; a close no span holds is not attributed.
		expect(controllerSessions([csRun('x', [{ session: 'A' }], { stepClose: '2026-10-15T10:30:00Z' })], stub(logs))[0].finished).toEqual(['x'])
		expect(controllerSessions([csRun('x', [{ session: 'A' }], { close: '2026-10-15T23:00:00Z' })], stub(logs))[0].finished).toEqual([])
	})

	it('lists a session whose log is not here as missing, with null figures, after the present ones', () => {
		const rows = controllerSessions(
			[csRun('x', [{ session: 'B' }, { session: 'A' }], { close: '2026-10-15T10:30:00Z' }), csRun('y', [{ session: 'B' }])],
			stub(new Map([['A', [mreq('a1', '10:00'), mreq('a2', '11:00')]]])),
		)
		expect(rows.map((r) => r.session)).toEqual(['A', 'B'])
		expect(rows[1]).toEqual({
			harness: 'claude',
			session: 'B',
			missing: true,
			first: null,
			last: null,
			requests: null,
			cost: null,
			unpriced: 0,
			outputUnknown: 0,
			perRequestByQuarter: [null, null, null, null],
			runs: ['x', 'y'],
			finished: [],
		})
		expect(rows[0].finished).toEqual(['x'])
	})

	it('counts a request copied into a resumed or forked session once', () => {
		const owned = mreq('r1', '10:00', 1000, { owned: true })
		const copy = mreq('r1', '09:00', 1000, { owned: false })
		const cop = controllerSessions(
			[csRun('x', [{ session: 'S1', harness: 'copilot' }, { session: 'S2', harness: 'copilot' }])],
			stub(new Map([['S1', [owned]], ['S2', [copy, mreq('r2', '11:00')]]])),
		)
		expect(Object.fromEntries(cop.map((r) => [r.session, r.requests]))).toEqual({ S1: 1, S2: 1 })
		// Claude Code: the earlier-starting session keeps a shared id.
		const shared = mreq('c1', '10:00')
		const cl = controllerSessions(
			[csRun('x', [{ session: 'late' }, { session: 'early' }])],
			stub(new Map([['late', [shared, mreq('c3', '12:00')]], ['early', [mreq('c0', '09:00'), shared]]])),
		)
		expect(Object.fromEntries(cl.map((r) => [r.session, r.requests]))).toEqual({ early: 2, late: 1 })
		// A start tie: the transcript born first keeps it.
		const tie = (born) =>
			Object.fromEntries(
				controllerSessions([csRun('x', [{ session: 'P' }, { session: 'Q' }])], stub(new Map([['P', [shared]], ['Q', [shared]]])), PRICES, { bornOf: (s) => born[s.session] }).map((r) => [
					r.session,
					r.requests,
				]),
			)
		expect(tie({ P: 2000, Q: 1000 })).toEqual({ P: 0, Q: 1 })
		expect(tie({ P: 1000, Q: 2000 })).toEqual({ P: 1, Q: 0 })
		// Ids are scoped per harness: a Copilot and a Claude request may share one.
		const mixed = controllerSessions([csRun('x', [{ session: 'P' }, { session: 'C', harness: 'copilot' }])], stub(new Map([['P', [shared]], ['C', [shared]]])))
		expect(mixed.map((r) => r.requests)).toEqual([1, 1])
	})

	it('reads only work.sessions, and infers the harness of an old-shape entry from its actor', () => {
		const logs = new Map([['A', [mreq('a', '10:00')]]])
		expect(controllerSessions([{ id: 'x', status: 'closed' }, { id: 'y', status: 'closed', work: { sessions: [], steps: [] } }], stub(logs))).toEqual([])
		expect(controllerSessions([{ id: 'z', status: 'closed', work: { sessions: [{ session: '' }, { actor: 'u/x' }], steps: [] } }], stub(logs))).toEqual([])
		const old = { id: 'o', status: 'closed', work: { sessions: [{ actor: 'u/claude-1234abcd', session: 'A' }], steps: [] } }
		const seen = []
		const [row] = controllerSessions([old], (s) => (seen.push(s), logs.get(s.session)))
		expect(row.harness).toBe('claude')
		expect(seen).toEqual([{ harness: 'claude', session: 'A' }])
		const [cop] = controllerSessions([{ id: 'p', status: 'closed', work: { sessions: [{ actor: 'u/someone', session: 'A' }], steps: [] } }], stub(logs))
		expect(cop.harness).toBe('copilot')
	})

	it('reads a session once however many runs name it, and never finishes an open run', () => {
		let reads = 0
		const logs = new Map([['A', [mreq('a1', '10:00'), mreq('a2', '11:00')]]])
		const rows = controllerSessions(
			[csRun('open', [{ session: 'A' }], { status: 'open', close: '2026-10-15T10:30:00Z' }), csRun('done', [{ session: 'A' }, { session: 'A' }], { close: '2026-10-15T10:30:00Z' })],
			(s) => (reads++, logs.get(s.session)),
		)
		expect(reads).toBe(1)
		expect(rows[0]).toMatchObject({ runs: ['open', 'done'], finished: ['done'] })
	})
})

describe('sessionReader', () => {
	let tmp
	const jsonl = (file, entries) => writeFileSync(file, entries.map((e) => JSON.stringify(e)).join('\n') + '\n')
	const usage = { input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 100, cache_creation_input_tokens: 20 }
	const assistant = (requestId, timestamp) => ({ type: 'assistant', timestamp, requestId, message: { model: 'claude-opus-5-5', stop_reason: 'end_turn', usage, content: [] } })
	beforeEach(() => {
		tmp = mkdtempSync(join(tmpdir(), 'calibrate-reader-'))
	})
	afterEach(() => rmSync(tmp, { recursive: true, force: true }))

	it('reads only the main transcript of a Claude Code session listed under its exact id', () => {
		const SESSION = '6f26e090-4089-4a32-bdd2-c49ba9c91d0b'
		const projects = join(tmp, 'projects')
		const dir = join(projects, '-w-bd')
		mkdirSync(join(dir, SESSION, 'subagents'), { recursive: true })
		jsonl(join(dir, `${SESSION}.jsonl`), [{ type: 'user', timestamp: '2026-10-15T10:00:00Z', message: { content: 'hi' } }, assistant('req-main', '2026-10-15T10:00:05Z')])
		jsonl(join(dir, SESSION, 'subagents', 'agent-a.jsonl'), [assistant('req-sub', '2026-10-15T10:01:00Z')])
		const { mainOf, bornOf } = sessionReader({ sessionsDir: join(tmp, 'none'), projectsDir: projects })
		const reqs = mainOf({ harness: 'claude', session: SESSION })
		expect(reqs.map((r) => r.id)).toEqual(['req-main'])
		expect(reqs[0].tokens.cache_read).toBe(100)
		expect(mainOf({ harness: 'claude', session: `../-w-bd/${SESSION}` })).toBe(null)
		expect(mainOf({ harness: 'claude', session: SESSION.slice(-8) })).toBe(null)
		expect(mainOf({ harness: 'claude', session: '00000000-0000-0000-0000-000000000000' })).toBe(null)
		expect(mainOf({ harness: 'claude', session: 42 })).toBe(null)
		expect(typeof bornOf({ harness: 'claude', session: SESSION })).toBe('number')
		expect(bornOf({ harness: 'claude', session: SESSION.slice(-8) })).toBe(0)
		expect(bornOf({ harness: 'copilot', session: SESSION })).toBe(0)
	})

	it("reads only a Copilot session's main requests, under its exact id", () => {
		const SID = '0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0'
		const sessions = join(tmp, 'sessions')
		mkdirSync(join(sessions, SID), { recursive: true })
		const record = (apiCallId, timestamp, agentId) => ({
			type: 'session.usage_record',
			timestamp,
			...(agentId ? { agentId } : {}),
			data: { usage: { model: 'claude-opus-5.5', apiCallId, inputTokens: 50, outputTokens: 5, cacheReadTokens: 30, cacheWriteTokens: 0, duration: 1000, copilotUsage: { totalNanoAiu: 1e9 } } },
		})
		jsonl(join(sessions, SID, 'events.jsonl'), [record('c-main', '2026-10-15T10:00:05Z'), record('c-sub', '2026-10-15T10:01:05Z', 'agent-1')])
		const { mainOf } = sessionReader({ sessionsDir: sessions, projectsDir: join(tmp, 'none') })
		const reqs = mainOf({ harness: 'copilot', session: SID })
		expect(reqs.map((r) => r.id)).toEqual(['c-main'])
		expect(reqs[0].owned).toBe(true)
		expect(mainOf({ harness: 'copilot', session: SID.slice(-8) })).toBe(null)
		expect(mainOf({ harness: 'copilot', session: `../sessions/${SID}` })).toBe(null)
		expect(mainOf({ harness: 'codex', session: SID })).toBe(null)
	})

	it('treats missing directories as no session', () => {
		const { mainOf, bornOf } = sessionReader({ sessionsDir: undefined, projectsDir: join(tmp, 'absent') })
		expect(mainOf({ harness: 'copilot', session: 'x' })).toBe(null)
		expect(mainOf({ harness: 'claude', session: 'x' })).toBe(null)
		expect(bornOf({ harness: 'claude', session: 'x' })).toBe(0)
	})
})

const issue = (id, status, metadata = {}) => ({ id, status, created_at: '2026-10-15T01:00:00Z', metadata: { playbook: { name: 'change', role: 'run', vars: {} }, ...metadata } })
const history = (id) => JSON.stringify([{ issue_id: id, op: 'created', ts: '2026-10-15T01:00:00Z', actor: 'Quang Le' }])

describe('calibrate CLI', () => {
	let bin
	beforeEach(() => {
		bin = mkdtempSync(join(tmpdir(), 'calibrate-bd-'))
		const issues = [issue('squid-a.1', 'closed'), issue('squid-b.1', 'open'), issue('squid-c.1', 'closed', { work: { sessions: [], steps: [] } })]
		// A stand-in for bd that logs every call: a.1 has no review step, b.1's lookup fails, and nobody's sessions are here.
		writeFileSync(
			join(bin, 'bd'),
			[
				'#!/bin/sh',
				`echo "$*" >> "${bin}/calls"`,
				'case " $* " in',
				`  *" list --all -n 0 --json "*) echo '${JSON.stringify(issues)}' ;;`,
				`  *" show squid-a.1.review "*) echo 'issue not_found' >&2; exit 3 ;;`,
				`  *" show squid-b.1.review "*) echo 'server unreachable' >&2; exit 8 ;;`,
				`  *" show "*) echo '{"status":"closed","dependents":[]}' ;;`,
				...['squid-a.1', 'squid-b.1', 'squid-c.1'].map((id) => `  *" history ${id} "*) echo '${history(id)}' ;;`),
				`  *" list "*) echo '[]' ;;`,
				'  *" update "*) exit 0 ;;',
				'esac',
				'',
			].join('\n'),
		)
		chmodSync(join(bin, 'bd'), 0o755)
	})
	afterEach(() => rmSync(bin, { recursive: true, force: true }))

	it('reports, leaves unreadable follow-ups unknown, and writes no trace that stands for nothing', () => {
		const script = fileURLToPath(new URL('./calibrate.mjs', import.meta.url))
		let out
		try {
			out = execFileSync('node', [script, '--sessions', bin, '--write'], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, stdio: ['ignore', 'pipe', 'pipe'] })
		} catch (e) {
			throw new Error(`exit ${e.status}: ${e.stderr}`, { cause: e })
		}
		expect(out).toContain('3 change playbook runs')
		expect(out).toMatch(/\| squid-a\.1 \|([^|]*\|){8} 0 \|/)
		expect(out).toMatch(/\| squid-b\.1 \|([^|]*\|){8} \? \|/)
		expect(out).toContain('none: no agent sessions')
		expect(out).toContain('## Controller sessions')
		expect(out).toContain('No traced session on this machine.')
		const calls = readFileSync(join(bin, 'calls'), 'utf8')
		// a.1 and b.1 have no agent sessions, and c.1 already has a stored trace: nothing to write.
		expect(calls).not.toContain(' update ')
	})

	// Runs calibrate --json over one stepless run, bd-x.1 (10:00 to 11:00), whose Claude Code session holds two
	// still-running workflows: wf_gate, whose first prompt names only bd-gate and bd-core, and wf_theirs, whose first
	// prompt names bd-y.1.implement, which bd knows. showCases are case arms answering bd's `show` for those ids.
	const traced = (showCases) => {
		const script = fileURLToPath(new URL('./calibrate.mjs', import.meta.url))
		const ACTOR = 'Quang Le/claude-a9c91d0b'
		const events = [
			{ issue_id: 'bd-x.1', op: 'created', ts: '2026-10-15T10:00:00Z', actor: ACTOR },
			{ issue_id: 'bd-x.1', op: 'closed', ts: '2026-10-15T11:00:00Z', actor: ACTOR },
		]
		writeFileSync(
			join(bin, 'bd'),
			[
				'#!/bin/sh',
				`echo "$*" >> "${bin}/calls"`,
				'case " $* " in',
				`  *" list --all -n 0 --json "*) echo '${JSON.stringify([issue('bd-x.1', 'closed')])}' ;;`,
				...showCases,
				`  *" show "*) echo '{"status":"closed","dependents":[]}' ;;`,
				`  *" history bd-x.1 "*) echo '${JSON.stringify(events)}' ;;`,
				`  *" list "*) echo '[]' ;;`,
				'esac',
				'',
			].join('\n'),
		)
		chmodSync(join(bin, 'bd'), 0o755)
		const projects = join(bin, 'projects')
		const dir = join(projects, '-w-bd')
		const SESSION = '6f26e090-4089-4a32-bdd2-c49ba9c91d0b'
		const jsonl = (file, entries) => writeFileSync(file, entries.map((e) => JSON.stringify(e)).join('\n') + '\n')
		mkdirSync(dir, { recursive: true })
		jsonl(join(dir, `${SESSION}.jsonl`), [{ type: 'user', timestamp: '2026-10-15T10:00:00Z', message: { content: 'hello' } }])
		// A workflow still running (no <session>/workflows/<wf>.json): one claim agent, first prompted with `prompt`.
		const running = (wf, prompt, at) => {
			const flow = join(dir, SESSION, 'subagents', 'workflows', wf)
			mkdirSync(flow, { recursive: true })
			jsonl(join(flow, 'journal.jsonl'), [{ type: 'started', agentId: 'k', label: 'claim' }])
			jsonl(join(flow, 'agent-k.jsonl'), [
				{ type: 'user', message: { content: prompt } },
				{
					type: 'assistant',
					timestamp: at,
					requestId: `${wf}-k`,
					message: { model: 'claude-opus-5-5', stop_reason: 'end_turn', usage: { input_tokens: 1, output_tokens: 1, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 }, content: [] },
				},
			])
		}
		running('wf_gate', 'Run bd-gate: dir=/w on bd-core', '2026-10-15T10:25:00Z')
		running('wf_theirs', 'Claim bd-y.1.implement.', '2026-10-15T10:25:01Z')
		const r = spawnSync('node', [script, '--json', '--sessions', bin, '--projects', projects], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } })
		return { status: r.status, stdout: r.stdout, stderr: r.stderr, calls: readFileSync(join(bin, 'calls'), 'utf8') }
	}
	const labelsOf = (stdout) =>
		JSON.parse(stdout)
			.runs.find((x) => x.id === 'bd-x.1')
			.work.steps.flatMap((s) => s.agents)
			.map((a) => a.label)

	it('keeps a running workflow whose prompt names only ids bd does not know, and leaves out one naming an issue bd knows, as trace-run does', () => {
		const out = traced([`  *" show bd-core "*) echo 'issue not_found' >&2; exit 3 ;;`, `  *" show bd-gate "*) echo 'issue not_found' >&2; exit 3 ;;`])
		if (out.status !== 0) throw new Error(`exit ${out.status}: ${out.stderr}`)
		expect(out.status).toBe(0)
		const r = JSON.parse(out.stdout).runs.find((x) => x.id === 'bd-x.1')
		expect(r.traced).toBe('backfilled')
		const labels = r.work.steps.flatMap((s) => s.agents).map((a) => a.label)
		expect(labels).toContain('wf_gate:claim')
		expect(labels.filter((l) => l.startsWith('wf_theirs'))).toEqual([])
		expect(r.work.other_work_requests).toBe(1)
		expect(out.calls).toContain('show bd-core --json')
		expect(out.calls).toContain('show bd-gate --json')
		expect(out.calls).toContain('show bd-y.1.implement --json')
		// Ids in the run are never asked about.
		expect(out.calls).not.toContain('show bd-x.1.implement')
		expect(out.stderr).not.toContain('not_found')
		expect(out.stderr).not.toContain('could not check issue ids')
		// The session's main transcript holds only a user entry: the workflow agents' requests are not its main thread.
		const controllers = JSON.parse(out.stdout).aggregate.controllers
		expect(controllers.length).toBe(1)
		expect(controllers[0]).toMatchObject({ harness: 'claude', session: '6f26e090-4089-4a32-bdd2-c49ba9c91d0b', missing: false, runs: ['bd-x.1'], requests: 0 })
	})

	it('warns once when bd cannot check the ids, keeps the workflow and still reports', () => {
		const out = traced([`  *" show bd-core "*) echo 'server unreachable' >&2; exit 8 ;;`, `  *" show bd-gate "*) echo 'server unreachable' >&2; exit 8 ;;`])
		if (out.status !== 0) throw new Error(`exit ${out.status}: ${out.stderr}`)
		expect(out.status).toBe(0)
		expect(out.stderr.split('could not check issue ids with bd').length - 1).toBe(1)
		expect(labelsOf(out.stdout)).toContain('wf_gate:claim')
	})
})
