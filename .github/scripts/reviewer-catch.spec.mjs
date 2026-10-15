import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import { aggregate, bandOf, matchFindings, observe, pairPasses, parseLabel, passesOf, readJournals, render, runOf, validatorsOf, verdictOf } from './reviewer-catch.mjs'

describe('parseLabel', () => {
	it.each([
		['review:code:r0', { kind: 'code', round: 0, type: 'real' }],
		['review:security:r12', { kind: 'security', round: 12, type: 'real' }],
		['review:code:r1@shadow:gpt-6-astra-xhigh', { kind: 'code', round: 1, type: 'shadow', shadow: { model: 'gpt-6-astra', effort: 'xhigh' } }],
		['review:code:r1@shadow:claude-opus-5.5-high', { kind: 'code', round: 1, type: 'shadow', shadow: { model: 'claude-opus-5.5', effort: 'high' } }],
	])('%s', (label, want) => expect(parseLabel(label)).toEqual(want))

	it('is null for anything else, an unknown shadow effort and a suffix other than shadow', () => {
		for (const label of ['validate:r0:F1', 'planner:draft', 'review:code:confirm-r0@strong', 'review:code:r0@escalated', 'review:code:r0@shadow:gpt-6-astra-loud', 'review:code:r0@shadow:high', null, undefined])
			expect(parseLabel(label)).toBeNull()
	})
})

const finding = (file, line, claim) => ({ file, line, claim, severity: 'minor', category: 'correctness', evidence: 'e' })
const pass = (over) => ({ journal: 'run1', kind: 'code', round: 0, type: 'real', model: 'sonnet', effort: 'medium', prompt: 'P', findings: [], failed: false, ...over })
const agentOf = (label, over = {}) => ({ label, model: 'claude-opus-5.5', effort: 'high', prompt: 'P', result: { findings: [] }, finding: null, ...over })

describe('passesOf', () => {
	it('keeps review agents only, takes findings from the result and fails a pass without one', () => {
		const got = passesOf({
			run: 'run1',
			agents: [
				agentOf('review:code:r0', { result: { findings: [finding('a.ts', 1, 'x')] } }),
				agentOf('review:security:r0', { result: null }),
				agentOf('validate:r0:F1', { result: { valid: true } }),
				agentOf('planner:draft'),
			],
		})
		expect(got.map((p) => [p.label, p.kind, p.type, p.failed, p.findings?.length ?? null])).toEqual([
			['review:code:r0', 'code', 'real', false, 1],
			['review:security:r0', 'security', 'real', true, null],
		])
		expect(got[0]).toMatchObject({ journal: 'run1', model: 'claude-opus-5.5', effort: 'high', prompt: 'P' })
	})

	it("falls back to a shadow's label for the model and effort when the session log is not here", () => {
		const [p] = passesOf({ run: 'r', agents: [agentOf('review:code:r0@shadow:gpt-6-astra-xhigh', { model: 'unknown', effort: null })] })
		expect(p).toMatchObject({ type: 'shadow', model: 'gpt-6-astra', effort: 'xhigh' })
		const [real] = passesOf({ run: 'r', agents: [agentOf('review:code:r0', { model: null, effort: null })] })
		expect(real).toMatchObject({ model: 'unknown', effort: 'unknown' })
	})
})

describe('pairPasses', () => {
	const real = pass({ findings: [] })
	const shadow = pass({ type: 'shadow', model: 'gpt-6-astra', effort: 'xhigh' })

	it('pairs a shadow with the real pass when the prompts hash alike', () => {
		const { pairs, skipped } = pairPasses([real, shadow])
		expect(pairs).toEqual([{ source: 'shadow', a: real, b: shadow }])
		expect(skipped).toEqual({ differentPrompt: 0, failed: 0 })
	})

	it('skips a pair whose prompts differ, and never pairs a failed pass', () => {
		expect(pairPasses([real, { ...shadow, prompt: 'Q' }])).toMatchObject({ pairs: [], skipped: { differentPrompt: 1 } })
		expect(pairPasses([real, { ...shadow, failed: true, findings: null }])).toMatchObject({ pairs: [], skipped: { failed: 1 } })
	})

	it('pairs nothing across kinds, rounds or runs, nor two real passes', () => {
		expect(pairPasses([real, { ...shadow, kind: 'security' }]).pairs).toEqual([])
		expect(pairPasses([real, { ...shadow, round: 1 }]).pairs).toEqual([])
		expect(pairPasses([real, { ...shadow, journal: 'run2' }]).pairs).toEqual([])
		expect(pairPasses([real, { ...real }]).pairs).toEqual([])
	})
})

describe('matchFindings', () => {
	it('matches lines up to 5 apart in the same file', () => {
		expect(matchFindings([finding('a.ts', 10, 'x')], [finding('a.ts', 13, 'y')]).matches).toEqual([[0, 0]])
	})

	it('does not match lines 7 apart, even with the same claim', () => {
		expect(matchFindings([finding('a.ts', 10, 'same claim text')], [finding('a.ts', 17, 'same claim text')])).toEqual({ matches: [], aOnly: [0], bOnly: [0] })
	})

	it('matches an absolute path with a relative one by basename', () => {
		expect(matchFindings([finding('/Users/q/wt/src/lib/a.ts', 4, 'x')], [finding('src/lib/a.ts', 4, 'y')]).matches).toEqual([[0, 0]])
		expect(matchFindings([finding('src/lib/a.ts', 4, 'x')], [finding('src/lib/b.ts', 4, 'x')]).matches).toEqual([])
	})

	it('compares claims when a line is missing', () => {
		const a = finding('a.ts', null, 'The focus ring is clipped by overflow hidden on the menu')
		expect(matchFindings([a], [finding('a.ts', 40, 'Overflow hidden on the menu clips the focus ring')]).matches).toEqual([[0, 0]])
		expect(matchFindings([a], [finding('a.ts', 40, 'Missing test for keyboard navigation in submenus')]).matches).toEqual([])
	})

	it('matches one to one, best score first', () => {
		const got = matchFindings([finding('a.ts', 10, 'x'), finding('a.ts', 12, 'y')], [finding('a.ts', 12, 'z')])
		expect(got).toEqual({ matches: [[1, 0]], aOnly: [0], bOnly: [] })
	})
})


describe('validatorsOf', () => {
	it("joins a validator's verdict to the finding it was given, by file basename and collapsed claim", () => {
		const verdicts = validatorsOf({
			run: 'r',
			agents: [
				agentOf('validate:r0:F1', { result: { valid: true, blocking: true, reasoning: 'r' }, finding: { file: '/abs/src/a.ts', line: 3, claim: 'The  menu\nloses focus' } }),
				agentOf('validate:r0:F2', { result: { valid: 'yes' }, finding: { file: 'b.ts', line: 1, claim: 'bad verdict' } }),
				agentOf('validate:r0:F3', { result: { valid: false }, finding: null }),
			],
		})
		expect(verdictOf(finding('src/a.ts', 3, 'The menu loses focus'), verdicts)).toEqual({ valid: true, blocking: true })
		expect(verdictOf(finding('b.ts', 1, 'bad verdict'), verdicts)).toBeNull()
		expect(verdicts.size).toBe(1)
	})
})

describe('observe and aggregate', () => {
	const A = [finding('a.ts', 10, 'one'), finding('a.ts', 50, 'two'), finding('b.ts', 5, 'three')]
	const B = [finding('a.ts', 11, 'one again'), finding('c.ts', 1, 'four')]
	const verdicts = new Map()
	const judge = (f, valid) => verdicts.set(`${f.file}\0${f.claim}`, { valid, blocking: false })
	judge(A[0], true) // matched to B[0], which inherits it
	judge(A[1], false)
	judge(B[1], true) // A misses it
	const pair = { source: 'shadow', a: pass({ findings: A }), b: pass({ findings: B, model: 'opus', effort: 'high' }) }

	it('counts both sides in both views', () => {
		const [a, b] = observe(pair, 3, verdicts)
		expect(a).toEqual({
			model: 'sonnet',
			effort: 'medium',
			vs: 'opus/high',
			band: 3,
			all: { raised: 3, matched: 1, missed: 1 },
			validated: { raised: 1, matched: 1, missed: 1, unverified: 1 },
		})
		expect(b).toEqual({
			model: 'opus',
			effort: 'high',
			vs: 'sonnet/medium',
			band: 3,
			all: { raised: 2, matched: 1, missed: 2 },
			validated: { raised: 2, matched: 1, missed: 0, unverified: 0 },
		})
		const rows = aggregate([a, b])
		expect(rows.all.find((r) => r.model === 'sonnet/medium')).toMatchObject({ pairs: 1, raised: 3, matched: 1, missed: 1, union: 4, catch: 0.75, thin: true, sameLevel: false })
		expect(rows.all.find((r) => r.model === 'opus/high')).toMatchObject({ raised: 2, missed: 2, union: 4, catch: 0.5, sameLevel: false })
		expect(rows.all.find((r) => r.model === 'sonnet/medium')).not.toHaveProperty('agreement')
		expect(rows.validated.find((r) => r.model === 'sonnet/medium')).toMatchObject({ raised: 1, matched: 1, missed: 1, union: 2, catch: 0.5, unverified: 1 })
		expect(rows.validated.find((r) => r.model === 'opus/high')).toMatchObject({ raised: 2, missed: 0, catch: 1, unverified: 0 })
	})

	it('lets a shadow finding inherit its matched partner verdict', () => {
		const shadow = { source: 'shadow', a: pass({ findings: [A[0]] }), b: pass({ type: 'shadow', model: 'haiku', effort: 'low', findings: [finding('a.ts', 9, 'unjudged'), finding('z.ts', 1, 'new')] }) }
		const [, b] = observe(shadow, 'unknown', verdicts)
		expect(b.validated).toEqual({ raised: 1, matched: 1, missed: 0, unverified: 1 })
	})

	const obs = (band, n) => Array.from({ length: n }, () => observe(pair, band, verdicts)[0])

	it('flags a row thin under 5 pairs and sorts by band', () => {
		const rows = aggregate([...obs('unknown', 1), ...obs(4, 4), ...obs(2, 5)]).all
		expect(rows.map((r) => [r.band, r.pairs, r.thin])).toEqual([
			[2, 5, false],
			[4, 4, true],
			['unknown', 1, true],
		])
		expect(rows[0]).toMatchObject({ raised: 15, matched: 5, missed: 5, catch: 0.75 })
	})

	const same = { source: 'shadow', a: pass({ findings: A, model: 'opus', effort: 'high' }), b: pass({ findings: B, model: 'opus', effort: 'high' }) }

	it('counts a pair once when both sides share a model and effort', () => {
		const rows = aggregate(observe(same, 3, verdicts)).all
		expect(rows).toHaveLength(1)
		expect(rows[0]).toMatchObject({ model: 'opus/high', vs: 'opus/high', pairs: 1, raised: 5, missed: 3, thin: true })
		expect(Object.keys(rows[0])).not.toContain('pair')
		expect(rows[0]).toMatchObject({ sameLevel: true, catch: null, matched: 2, raised: 5, agreement: 0.4 })
		const validated = aggregate(observe(same, 3, verdicts)).validated[0]
		expect(validated).toMatchObject({ sameLevel: true, catch: null, raised: 3, matched: 2 })
		expect(validated.agreement).toBeCloseTo(2 / 3)
	})

	it('gives agreement 0 to a same-level pair with no shared finding', () => {
		const a = pass({ model: 'opus', effort: 'high', findings: [finding('x.ts', 1, 'p')] })
		const b = pass({ model: 'opus', effort: 'high', findings: [finding('y.ts', 1, 'q')] })
		const rows = aggregate(observe({ source: 'shadow', a, b }, 3, verdicts)).all
		expect(rows).toHaveLength(1)
		expect(rows[0]).toMatchObject({ raised: 2, matched: 0, agreement: 0, catch: null, sameLevel: true })
	})

	it('gives agreement null to a same-level pair that raised nothing', () => {
		const a = pass({ model: 'opus', effort: 'high', findings: [] })
		const b = pass({ model: 'opus', effort: 'high', findings: [] })
		const rows = aggregate(observe({ source: 'shadow', a, b }, 3, verdicts)).all
		expect(rows[0]).toMatchObject({ raised: 0, agreement: null, catch: null, sameLevel: true })
	})

	it('flags three same-model pairs thin', () => {
		const rows = aggregate(Array.from({ length: 3 }, () => observe(same, 3, verdicts)).flat())
		expect(rows.all.map((r) => [r.pairs, r.thin])).toEqual([[3, true]])
		expect(rows.validated.map((r) => [r.pairs, r.thin])).toEqual([[3, true]])
	})
})


describe('render', () => {
	it('prints both tables without any claim text or path', () => {
		const pair = { a: pass({ findings: [finding('secret/path.ts', 3, 'Secret claim text')] }), b: pass({ type: 'shadow', model: 'opus', effort: 'high' }) }
		const observations = observe(pair, 2, new Map())
		const out = render({
			journals: 1,
			passes: 2,
			failed: 0,
			pairs: [{ prompt: 'same', band: 2 }],
			skipped: { differentPrompt: 3, failed: 0 },
			rows: aggregate(observations),
		})
		expect(out).toContain('# Reviewer catch rate')
		expect(out).toContain('## All findings')
		expect(out).toContain('## Validated findings only')
		expect(out).toContain('| band | model/effort | vs | pairs | raised | matched | missed | catch | agree | thin |')
		expect(out).toContain('| 2 | sonnet/medium | opus/high | 1 | 1 | 0 | 0 | 100% | – | thin |')
		expect(out).toContain('3 with different prompts')
		expect(out).toContain('catch = raised / union')
		expect(out).toContain('50% to 100% by construction')
		expect(out).toContain('agree = matched / raised')
		expect(out).not.toContain('(union - missed) / union')
		expect(out).not.toMatch(/Secret claim|secret\/path|path\.ts/)
	})

	it('shows agreement and no catch on same-level rows', () => {
		const A = [finding('a.ts', 10, 'one'), finding('a.ts', 50, 'two'), finding('b.ts', 5, 'three')]
		const B = [finding('a.ts', 11, 'one again'), finding('c.ts', 1, 'four')]
		const verdicts = new Map()
		verdicts.set(`${A[0].file}\0${A[0].claim}`, { valid: true, blocking: false })
		verdicts.set(`${A[1].file}\0${A[1].claim}`, { valid: false, blocking: false })
		verdicts.set(`${B[1].file}\0${B[1].claim}`, { valid: true, blocking: false })
		const rows = aggregate(observe({ a: pass({ findings: A, model: 'opus', effort: 'high' }), b: pass({ findings: B, model: 'opus', effort: 'high' }) }, 3, verdicts))
		const out = render({ journals: 1, passes: 2, failed: 0, pairs: [{ prompt: 'same', band: 3 }], skipped: { differentPrompt: 0, failed: 0 }, rows })
		expect(out).toContain('| 3 | opus/high | opus/high | 1 | 5 | 2 | 3 | – | 40% | thin |')
		expect(out).toContain('| 3 | opus/high | opus/high | 1 | 3 | 2 | 1 | – | 67% | thin |')
	})
})


describe('bandOf', () => {
	const issues = {
		'squid-c': { metadata: { score: { complexity: 4 }, score_judge: { complexity: 3 }, complexity_estimate: { score: 2 } } },
		'squid-j': [{ metadata: { score_judge: { complexity: 3 }, complexity_estimate: { score: 2 } } }],
		'squid-e': { metadata: { complexity_estimate: { score: 2 } } },
		'squid-n': { metadata: {} },
		'squid-r.1': { metadata: { playbook: { role: 'run' }, score_judge: { complexity: 5 } } },
		'squid-r.1.implement': { metadata: { playbook: { role: 'step', run: 'squid-r.1' } } },
	}
	const stub = () => {
		const calls = []
		const bd = (args) => {
			calls.push(args)
			if (!(args[1] in issues)) throw new Error('issue not_found')
			return issues[args[1]]
		}
		return { calls, bd }
	}

	it('takes the confirmed, else judged, else estimated complexity', () => {
		const { bd } = stub()
		expect(bandOf('squid-c', bd)).toEqual({ band: 4, source: 'confirmed' })
		expect(bandOf('squid-j', bd)).toEqual({ band: 3, source: 'judged' })
		expect(bandOf('squid-e', bd)).toEqual({ band: 2, source: 'estimate' })
		expect(bandOf('squid-n', bd)).toEqual({ band: 'unknown', source: null })
	})

	it('resolves a step to its run', () => {
		const { calls, bd } = stub()
		expect(bandOf('squid-r.1.implement', bd)).toEqual({ band: 5, source: 'judged' })
		expect(calls).toEqual([
			['show', 'squid-r.1.implement'],
			['show', 'squid-r.1'],
		])
	})

	it('is unknown when bd throws', () => {
		expect(
			bandOf('squid-x', () => {
				throw new Error('server unreachable')
			}),
		).toEqual({ band: 'unknown', source: null })
	})

	it('never passes an id that is not a plain issue id to bd', () => {
		const { calls, bd } = stub()
		expect(bandOf('x; rm -rf', bd)).toEqual({ band: 'unknown', source: null })
		expect(bandOf('X/../y', bd)).toEqual({ band: 'unknown', source: null })
		expect(calls).toEqual([])
	})

	it('shows each id once per cache', () => {
		const { calls, bd } = stub()
		const cache = new Map()
		bandOf('squid-r.1.implement', bd, cache)
		bandOf('squid-r.1', bd, cache)
		bandOf('squid-r.1.implement', bd, cache)
		bandOf('squid-missing', bd, cache)
		bandOf('squid-missing', bd, cache)
		expect(calls.map((c) => c[1])).toEqual(['squid-r.1.implement', 'squid-r.1', 'squid-missing'])
	})
})


describe('runOf', () => {
	it('takes the review step as its run, else the issue', () => {
		expect(runOf({ reviewStep: 'squid-a.1.review', issue: 'squid-a' })).toBe('squid-a.1')
		expect(runOf({ issue: 'squid-a' })).toBe('squid-a')
		expect(runOf({ reviewStep: null, issue: null })).toBeNull()
		expect(runOf(null)).toBeNull()
	})
})


const RUN_A = 'aaaaaaaa-0000-4000-8000-000000000001'
const RUN_B = 'bbbbbbbb-0000-4000-8000-000000000002'
const jsonl = (file, rows) => writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + '\n{not json\n')
const rec = (label, prompt, result, over = {}) => ({ type: 'agent', label, kind: 'code-review', model: null, effort: null, prompt_sha256: prompt, result, ...over })
const startedEvt = (agentId, run, label, model) => ({ type: 'subagent.started', agentId, data: { agentName: 'code-review', agentDisplayName: label, workflowRunId: run, model } })
const configuredEvt = (agentId, effort) => ({ type: 'subagent.configured', agentId, data: { reasoningEffort: effort } })

describe('readJournals', () => {
	let sessions
	beforeEach(() => {
		sessions = mkdtempSync(join(tmpdir(), 'reviewer-catch-sessions-'))
	})
	afterEach(() => rmSync(sessions, { recursive: true, force: true }))

	it('reads the recorded agents with the model and effort the session log says they ran with, each label and prompt once', () => {
		const dir = join(sessions, 's1')
		mkdirSync(join(dir, 'files', 'workflow-agents'), { recursive: true })
		jsonl(join(dir, 'events.jsonl'), [startedEvt('a1', RUN_A, 'review:code:r0', 'claude-opus-5.5'), configuredEvt('a1', 'high'), startedEvt('a2', RUN_A, 'review:code:r0@shadow:gpt-6-astra-xhigh', 'gpt-6-astra'), configuredEvt('a2', 'xhigh')])
		jsonl(join(dir, 'files', 'workflow-agents', `${RUN_A}.jsonl`), [
			{ type: 'run', workflow: 'plan-implement-review', reviewStep: 'squid-a.1.review', issue: 'squid-a', tier: 'standard' },
			rec('review:code:r0', 'P', null),
			// Replayed by a resume: the last record stands.
			rec('review:code:r0', 'P', { findings: [] }),
			rec('review:code:r0@shadow:gpt-6-astra-xhigh', 'P', { findings: [] }, { model: 'gpt-6-astra', effort: 'xhigh' }),
			rec('validate:r0:F1', 'V', { valid: true }, { finding: { file: 'a.ts', line: 1, claim: 'c' } }),
		])
		// A session without recordings, a stray file, and a log with no events yet.
		mkdirSync(join(sessions, 's2'))
		mkdirSync(join(sessions, 's3', 'files', 'workflow-agents'), { recursive: true })
		writeFileSync(join(sessions, 's3', 'files', 'workflow-agents', 'notes.txt'), 'x')
		jsonl(join(sessions, 's3', 'files', 'workflow-agents', `${RUN_B}.jsonl`), [rec('review:code:r0', 'P', { findings: [] }, { model: 'claude-opus-5.5', effort: 'low' })])
		const got = readJournals(sessions)
		expect(got.map((j) => j.run).toSorted()).toEqual([RUN_A, RUN_B])
		const a = got.find((j) => j.run === RUN_A)
		expect(a).toMatchObject({ workflow: 'plan-implement-review', args: { reviewStep: 'squid-a.1.review', issue: 'squid-a' } })
		expect(a.agents.map((x) => [x.label, x.model, x.effort, x.prompt])).toEqual([
			['review:code:r0', 'claude-opus-5.5', 'high', 'P'],
			['review:code:r0@shadow:gpt-6-astra-xhigh', 'gpt-6-astra', 'xhigh', 'P'],
			['validate:r0:F1', 'unknown', 'unknown', 'V'],
		])
		expect(a.agents[0].result).toEqual({ findings: [] })
		expect(a.agents[2].finding).toEqual({ file: 'a.ts', line: 1, claim: 'c' })
		// Without session events, what the workflow asked for stands.
		expect(got.find((j) => j.run === RUN_B).agents[0]).toMatchObject({ model: 'claude-opus-5.5', effort: 'low' })
	})
})

describe('reviewer-catch CLI', () => {
	const CLAIM = 'Fixture claim the menu loses focus'
	let tmp
	let sessions
	let bin

	beforeEach(() => {
		tmp = mkdtempSync(join(tmpdir(), 'reviewer-catch-cli-'))
		sessions = join(tmp, 'sessions')
		bin = join(tmp, 'bin')
		mkdirSync(bin)
		const found = finding('/fake/src/lib/a.ts', 12, CLAIM)
		const make = (id, run, rows, events) => {
			const dir = join(sessions, id)
			mkdirSync(join(dir, 'files', 'workflow-agents'), { recursive: true })
			jsonl(join(dir, 'files', 'workflow-agents', `${run}.jsonl`), rows)
			jsonl(join(dir, 'events.jsonl'), events)
		}
		make(
			's1',
			RUN_A,
			[
				{ type: 'run', workflow: 'plan-implement-review', reviewStep: 'squid-a.1.review', issue: 'squid-a' },
				rec('review:code:r0', 'P', { findings: [found] }),
				rec('review:code:r0@shadow:gpt-6-astra-xhigh', 'P', { findings: [{ ...found, file: 'src/lib/a.ts', line: 14 }, finding('b.ts', 3, 'other')] }),
				rec('validate:r0:F1', 'V', { valid: true, blocking: true, reasoning: 'r' }, { finding: { file: found.file, line: 12, claim: CLAIM } }),
			],
			[startedEvt('a1', RUN_A, 'review:code:r0', 'claude-opus-5.5'), configuredEvt('a1', 'high'), startedEvt('a2', RUN_A, 'review:code:r0@shadow:gpt-6-astra-xhigh', 'gpt-6-astra'), configuredEvt('a2', 'xhigh')],
		)
		make(
			's2',
			RUN_B,
			[
				{ type: 'run', workflow: 'plan-implement-review', reviewStep: null, issue: 'squid-b' },
				rec('review:code:r0', 'Q', { findings: [] }, { model: 'claude-opus-5.5', effort: 'high' }),
				rec('review:code:r0@shadow:claude-opus-5.5-low', 'Q', { findings: [finding('c.ts', 1, 'shadow only')] }, { model: 'claude-opus-5.5', effort: 'low' }),
			],
			[],
		)
		// A stand-in for bd that logs every call and knows both runs.
		writeFileSync(
			join(bin, 'bd'),
			[
				'#!/bin/sh',
				`echo "$*" >> "${bin}/calls"`,
				'case " $* " in',
				`  *" show squid-a.1 "*) echo '${JSON.stringify({ metadata: { score_judge: { complexity: 3 } } })}' ;;`,
				`  *" show squid-b "*) echo '${JSON.stringify([{ metadata: { complexity_estimate: { score: 2 } } }])}' ;;`,
				`  *) echo 'issue not_found' >&2; exit 3 ;;`,
				'esac',
				'',
			].join('\n'),
		)
		chmodSync(join(bin, 'bd'), 0o755)
	})
	afterEach(() => rmSync(tmp, { recursive: true, force: true }))

	const ROOT = '/fake/checkout'
	const run = (...args) => {
		const script = fileURLToPath(new URL('./reviewer-catch.mjs', import.meta.url))
		try {
			return execFileSync('node', [script, '--sessions', sessions, '--root', ROOT, ...args], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, stdio: ['ignore', 'pipe', 'pipe'] })
		} catch (e) {
			throw new Error(`exit ${e.status}: ${e.stderr}`, { cause: e })
		}
	}

	it('reports both tables with bands from bd, and no claim text', () => {
		const out = run()
		expect(out).toContain('2 journals, 4 review passes (0 failed). 2 pairs of real vs shadow passes.')
		expect(out).toContain('| 3 | claude-opus-5.5/high | gpt-6-astra/xhigh | 1 | 1 | 1 | 1 | 50% | – | thin |')
		expect(out).toContain('| 2 | claude-opus-5.5/high | claude-opus-5.5/low | 1 | 0 | 0 | 1 | 0% | – | thin |')
		expect(out).not.toMatch(/Fixture claim|shadow only|a\.ts|squid-a/)
	})

	it('prints JSON with the validator verdict joined, and only shows issues in bd', () => {
		const got = JSON.parse(run('--json'))
		expect(got.pairs).toHaveLength(2)
		const first = got.pairs.find((p) => p.run === 'squid-a.1')
		expect(first).toMatchObject({ workflow: 'plan-implement-review', source: 'shadow', band: 3, bandSource: 'judged', matched: 1, aOnly: 0, bOnly: 1 })
		expect(first.a).toEqual({ label: 'review:code:r0', model: 'claude-opus-5.5', effort: 'high', findings: 1 })
		expect(got.pairs.find((p) => p.run === 'squid-b')).toMatchObject({ band: 2, bandSource: 'estimate', b: { model: 'claude-opus-5.5', effort: 'low' } })
		// The real finding is valid by its own verdict, the shadow's match by inheritance; 'other' was never validated.
		expect(got.rows.validated.find((r) => r.band === 3 && r.model === 'claude-opus-5.5/high')).toMatchObject({ raised: 1, matched: 1, missed: 0, unverified: 0, sameLevel: false })
		expect(got.rows.validated.find((r) => r.band === 3 && r.model === 'gpt-6-astra/xhigh')).toMatchObject({ raised: 1, matched: 1, unverified: 1 })
		const calls = readFileSync(join(bin, 'calls'), 'utf8').trim().split('\n')
		expect(calls).toEqual([`-C ${ROOT} show squid-a.1 --json`, `-C ${ROOT} show squid-b --json`])
	})
})
