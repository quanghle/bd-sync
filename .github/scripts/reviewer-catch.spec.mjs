import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import {
	COMPUTED_TASK,
	SUBAGENT_HANDBACK,
	agentFacts,
	aggregate,
	bandOf,
	bugVerdict,
	canonicalModel,
	claudePassesOf,
	claudeValidatorsOf,
	encodeProject,
	findingsIn,
	handIssue,
	handPromptOf,
	handReview,
	matchBugs,
	matchFindings,
	namedIssues,
	observe,
	pairHandPasses,
	pairPasses,
	parseLabel,
	passesOf,
	projectDirs,
	promptOf,
	readClaudeJournals,
	readHandPasses,
	readJournals,
	render,
	report as reportFrom,
	reportOf,
	rubricVersion,
	runBandOf,
	runOf,
	validatorsOf,
	verdictOf,
	verdictsFromBugs,
} from './reviewer-catch.mjs'

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
		expect(pairs).toEqual([{ source: 'shadow', a: real, b: shadow, prompt: 'same' }])
		expect(skipped).toEqual({ differentPrompt: 0, failed: 0 })
	})

	it('keeps a pair whose prompt is unknown as unchecked', () => {
		expect(pairPasses([{ ...real, prompt: null }, shadow]).pairs.map((p) => p.prompt)).toEqual(['unchecked'])
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
			rubric: null,
			band: 3,
			all: { raised: 3, matched: 1, missed: 1 },
			validated: { raised: 1, matched: 1, missed: 1, unverified: 1 },
		})
		expect(b).toEqual({
			model: 'opus',
			effort: 'high',
			vs: 'sonnet/medium',
			rubric: null,
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

	const at = (rubric, n) => Array.from({ length: n }, () => observe(pair, 3, verdicts, rubric)[0])

	it('carries the rubric version on both sides', () => {
		expect(observe(pair, 3, verdicts, 2).map((o) => [o.band, o.rubric])).toEqual([
			[3, 2],
			[3, 2],
		])
	})

	it('keeps rows of the same band apart by rubric version, sorted by version with unknown last', () => {
		const rows = aggregate([...at(null, 1), ...at(3, 2), ...at(2, 3), ...obs(2, 1)]).all
		expect(rows.map((r) => [r.rubric, r.band, r.pairs])).toEqual([
			[2, 3, 3],
			[3, 3, 2],
			[null, 2, 1],
			[null, 3, 1],
		])
	})

	const same ={ source: 'shadow', a: pass({ findings: A, model: 'opus', effort: 'high' }), b: pass({ findings: B, model: 'opus', effort: 'high' }) }

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
		expect(out).toContain('| rubric | band | model/effort | vs | pairs | raised | matched | missed | catch | agree | thin |')
		expect(out).toContain('| unknown | 2 | sonnet/medium | opus/high | 1 | 1 | 0 | 0 | 100% | – | thin |')
		expect(out).toContain('rubric is the rubric version that band was scored under, and bands of different versions are not compared.')
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
		expect(out).toContain('| unknown | 3 | opus/high | opus/high | 1 | 5 | 2 | 3 | – | 40% | thin |')
		expect(out).toContain('| unknown | 3 | opus/high | opus/high | 1 | 3 | 2 | 1 | – | 67% | thin |')
	})

	it('prints the rubric version as v<N> in its leading column', () => {
		const pair = { a: pass({ findings: [finding('a.ts', 3, 'x')] }), b: pass({ type: 'shadow', model: 'opus', effort: 'high' }), prompt: 'same' }
		const out = render({ journals: 1, passes: 2, failed: 0, currentRubric: 3, pairs: [{ source: 'shadow', prompt: 'same', band: 2 }], skipped: { differentPrompt: 0, failed: 0 }, rows: aggregate(observe(pair, 2, new Map(), 2)) })
		expect(out).toContain('| v2 | 2 | sonnet/medium | opus/high | 1 | 1 | 0 | 0 | 100% | – | thin |')
		expect(out).not.toContain('| unknown |')
		expect(out).toContain('Current rubric (.bd/rubric.md): v3.')
	})

	it('counts pairs and unknown bands per source, and prints no claim, description, id or path', () => {
		const pair = { source: 'hand-shadow', a: pass({ description: 'Opus review of bd-zz', findings: [finding('secret/path.ts', 3, 'Secret claim text')] }), b: pass({ type: 'shadow', model: 'opus', effort: 'high' }), prompt: 'same' }
		const out = render({
			journals: 2,
			claudeJournals: 4,
			hand: 3,
			passes: 5,
			failed: 1,
			handPasses: 7,
			handFailed: 2,
			handVerdicts: 3,
			pairs: [
				{ source: 'shadow', prompt: 'same', band: 2, run: 'bd-zz' },
				{ source: 'claude-shadow', prompt: 'unchecked', band: 'unknown', run: 'bd-zz.2' },
				{ source: 'hand-shadow', prompt: 'same', band: 'unknown', run: null },
				{ source: 'hand-shadow', prompt: 'same', band: 3, run: 'bd-zz.1' },
			],
			skipped: { differentPrompt: 1, failed: 2, noShadow: 4 },
			rows: aggregate(observe(pair, 3, new Map())),
		})
		expect(out).toContain('2 Copilot workflow runs and 4 Claude Code workflow journals, 5 review passes (1 failed); 3 hand-run groups, 7 hand-run review passes (2 failed).')
		expect(out).toContain('4 pairs by source (band unknown): 1 Copilot real vs shadow (0), 1 Claude Code real vs shadow (1), 2 hand-run real vs shadow (1).')
		expect(out).toContain('Skipped: 1 with different prompts, 2 with a failed side, 4 hand-run prompts without both a real and a shadow pass. 1 with the prompt unchecked, 2 with the band unknown.')
		expect(out).toContain("3 hand-run findings got a verdict from bd (their change run's Finding bugs).")
		expect(out).toContain('Current rubric (.bd/rubric.md): unknown.')
		expect(out).toContain('hand-shadow pairs come from review subagents run outside workflows.')
		expect(out).toContain("Claude Code's claude-opus-5-5 is claude-opus-5.5")
		expect(out).not.toMatch(/Secret claim|secret\/path|path\.ts|bd-zz|Opus review/)
	})

	it('reads missing counts as 0', () => {
		const out = render({ pairs: [], rows: { all: [], validated: [] } })
		expect(out).toContain('0 Copilot workflow runs and 0 Claude Code workflow journals, 0 review passes (0 failed); 0 hand-run groups, 0 hand-run review passes (0 failed).')
		expect(out).toContain('0 pairs by source (band unknown): 0 Copilot real vs shadow (0), 0 Claude Code real vs shadow (0), 0 hand-run real vs shadow (0).')
		expect(out).toContain('No pairs.')
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
		expect(bandOf('squid-c', bd)).toEqual({ band: 4, source: 'confirmed', rubric: null })
		expect(bandOf('squid-j', bd)).toEqual({ band: 3, source: 'judged', rubric: null })
		expect(bandOf('squid-e', bd)).toEqual({ band: 2, source: 'estimate', rubric: null })
		expect(bandOf('squid-n', bd)).toEqual({ band: 'unknown', source: null, rubric: null })
	})

	it('takes the rubric version of the same object only, and only as an integer', () => {
		const versions = {
			'bd-c': { metadata: { score: { complexity: 4, rubric: 3 }, score_judge: { complexity: 3, rubric: 2 }, complexity_estimate: { score: 2, rubric: 1 } } },
			'bd-j': { metadata: { score_judge: { complexity: 3, rubric: 2 }, complexity_estimate: { score: 2, rubric: 3 } } },
			'bd-e': { metadata: { complexity_estimate: { score: 2, rubric: 1 } } },
			// The confirmed score has no rubric; the judge's version is not borrowed.
			'bd-v': { metadata: { score: { complexity: 2 }, score_judge: { complexity: 3, rubric: 2 } } },
			'bd-w': { metadata: { score_judge: { complexity: 3, rubric: '2' } } },
		}
		const bd = (args) => versions[args[1]]
		expect(bandOf('bd-c', bd)).toEqual({ band: 4, source: 'confirmed', rubric: 3 })
		expect(bandOf('bd-j', bd)).toEqual({ band: 3, source: 'judged', rubric: 2 })
		expect(bandOf('bd-e', bd)).toEqual({ band: 2, source: 'estimate', rubric: 1 })
		expect(bandOf('bd-v', bd)).toEqual({ band: 2, source: 'confirmed', rubric: null })
		expect(bandOf('bd-w', bd)).toEqual({ band: 3, source: 'judged', rubric: null })
	})

	it('resolves a step to its run', () => {
		const { calls, bd } = stub()
		expect(bandOf('squid-r.1.implement', bd)).toEqual({ band: 5, source: 'judged', rubric: null })
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
		).toEqual({ band: 'unknown', source: null, rubric: null })
	})

	it('never passes an id that is not a plain issue id to bd', () => {
		const { calls, bd } = stub()
		expect(bandOf('x; rm -rf', bd)).toEqual({ band: 'unknown', source: null, rubric: null })
		expect(bandOf('X/../y', bd)).toEqual({ band: 'unknown', source: null, rubric: null })
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
				`  *" show squid-a.1 "*) echo '${JSON.stringify({ metadata: { score_judge: { complexity: 3, rubric: 3 } } })}' ;;`,
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
			return execFileSync('node', [script, '--sessions', sessions, '--projects', join(tmp, 'projects'), '--root', ROOT, ...args], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, stdio: ['ignore', 'pipe', 'pipe'] })
		} catch (e) {
			throw new Error(`exit ${e.status}: ${e.stderr}`, { cause: e })
		}
	}

	it('reports both tables with bands from bd, and no claim text', () => {
		const out = run()
		expect(out).toContain('2 Copilot workflow runs and 0 Claude Code workflow journals, 4 review passes (0 failed); 0 hand-run groups, 0 hand-run review passes (0 failed).')
		expect(out).toContain('2 pairs by source (band unknown): 2 Copilot real vs shadow (0), 0 Claude Code real vs shadow (0), 0 hand-run real vs shadow (0).')
		expect(out).toContain('| v3 | 3 | claude-opus-5.5/high | gpt-6-astra/xhigh | 1 | 1 | 1 | 1 | 50% | – | thin |')
		expect(out).toContain('| unknown | 2 | claude-opus-5.5/high | claude-opus-5.5/low | 1 | 0 | 0 | 1 | 0% | – | thin |')
		expect(out).not.toMatch(/Fixture claim|shadow only|a\.ts|squid-a/)
	})

	it('prints JSON with the validator verdict joined, and only shows issues in bd', () => {
		const got = JSON.parse(run('--json'))
		expect(got.pairs).toHaveLength(2)
		const first = got.pairs.find((p) => p.run === 'squid-a.1')
		expect(first).toMatchObject({ workflow: 'plan-implement-review', source: 'shadow', band: 3, bandSource: 'judged', rubric: 3, prompt: 'same', matched: 1, aOnly: 0, bOnly: 1 })
		expect(first.a).toEqual({ label: 'review:code:r0', model: 'claude-opus-5.5', effort: 'high', findings: 1 })
		expect(got.pairs.find((p) => p.run === 'squid-b')).toMatchObject({ band: 2, bandSource: 'estimate', rubric: null, b: { model: 'claude-opus-5.5', effort: 'low' } })
		// The real finding is valid by its own verdict, the shadow's match by inheritance; 'other' was never validated.
		expect(got.rows.validated.find((r) => r.band === 3 && r.model === 'claude-opus-5.5/high')).toMatchObject({ raised: 1, matched: 1, missed: 0, unverified: 0, sameLevel: false })
		expect(got.rows.validated.find((r) => r.band === 3 && r.model === 'gpt-6-astra/xhigh')).toMatchObject({ raised: 1, matched: 1, unverified: 1 })
		const calls = readFileSync(join(bin, 'calls'), 'utf8').trim().split('\n')
		expect(calls).toEqual([`-C ${ROOT} show squid-a.1 --json`, `-C ${ROOT} show squid-b --json`])
	})
})

// ---------- Claude Code and hand-run sources ----------
const RELAY = '[Workflow harness — user request] The user asked for this workflow:\n  implement bd-x'
const task = (text) => `${COMPUTED_TASK} The task text below was computed at runtime by a workflow script. The computed task text follows:\n${text.replace(/^/gm, '  ')}`
const user = (content) => ({ type: 'user', message: { role: 'user', content } })
const assistant = (model = 'claude-opus-5-5', n = 0) => ({
	type: 'assistant',
	requestId: `req${n}`,
	timestamp: `2026-10-15T00:00:0${n}Z`,
	message: { model, usage: { input_tokens: 1, output_tokens: 1 }, content: [{ type: 'text', text: 'ok' }] },
})
const apiRequest = (effort) => ({ type: 'api-request', params: { output_config: { effort } } })
const said = (...content) => ({ type: 'assistant', message: { content } })
const text = (t) => ({ type: 'text', text: t })
const handback = (message) => ({ type: 'tool_use', name: SUBAGENT_HANDBACK, input: { message } })
const joined = (...ls) => ls.join('\n')

describe('canonicalModel', () => {
	it.each([
		['claude-opus-5-5', 'claude-opus-5.5'],
		['claude-opus-5.5', 'claude-opus-5.5'],
		['claude-sonnet-5-5-20261001', 'claude-sonnet-5.5'],
		['claude-opus-5-5[1m]', 'claude-opus-5.5'],
		['claude-haiku-4-5', 'claude-haiku-4.5'],
		['claude-opus-5', 'claude-opus-5'],
		['Claude-Opus-5-5', 'claude-opus-5.5'],
		['opus', 'opus'],
		['gpt-6-astra', 'gpt-6-astra'],
		['unknown', 'unknown'],
		[null, 'unknown'],
		['', 'unknown'],
	])('%s is %s', (id, want) => expect(canonicalModel(id)).toBe(want))
})

describe('promptOf', () => {
	it('takes the computed task, not the user-request relay before it', () => {
		expect(promptOf([user(RELAY), user(task('Review the diff.')), assistant()])).toBe(task('Review the diff.'))
	})

	it('joins the leading user entries when no computed-task entry is there', () => {
		expect(promptOf([user('one'), user([{ type: 'text', text: 'two' }, { type: 'image' }]), assistant()])).toBe('one\n\ntwo')
	})

	it('is null without a transcript, and ignores user entries after the first assistant entry', () => {
		expect(promptOf([])).toBeNull()
		expect(promptOf(null)).toBeNull()
		expect(promptOf([user('first'), assistant(), user(task('later'))])).toBe('first')
	})
})

describe('agentFacts', () => {
	it('takes the versioned id from the transcript over an alias in meta, and the effort from the transcript', () => {
		expect(agentFacts({ model: 'opus' }, [apiRequest('high'), user(task('x')), assistant('claude-opus-5-5')])).toEqual({ model: 'claude-opus-5.5', effort: 'high', prompt: task('x') })
	})

	it('keeps an alias when nothing names the version', () => {
		expect(agentFacts({ model: 'sonnet' }, [user('x')]).model).toBe('sonnet')
	})

	it('is unknown without meta or transcript', () => {
		expect(agentFacts(null, null)).toEqual({ model: 'unknown', effort: 'unknown', prompt: null })
	})

	it('takes a valid effort from meta over the transcript', () => {
		const entries = [apiRequest('high'), user('x'), assistant('claude-opus-5-5')]
		expect(agentFacts({ model: 'opus', effort: 'medium' }, entries).effort).toBe('medium')
		expect(agentFacts({ model: 'opus', effort: 'bogus' }, entries).effort).toBe('high')
	})
})

const started = (agentId, label) => ({ type: 'started', key: `k-${agentId}`, agentId, label, phase: 'Review' })
const result = (agentId, value) => ({ type: 'result', key: `k-${agentId}`, agentId, result: value })
const factsFrom = (table) => (id) => table[id] ?? { model: 'unknown', effort: 'unknown', prompt: null }

describe('claudePassesOf', () => {
	it('parses string results, fails a pass without a result, dedupes agents and skips escalated retries', () => {
		const journal = {
			wf: 'wf1',
			entries: [
				{ type: 'launched' },
				started('a1', 'review:code:r0'),
				started('a1', 'review:code:r0'),
				result('a1', JSON.stringify({ findings: [finding('a.ts', 1, 'x')] })),
				started('a2', 'review:code:r0@sonnet'),
				started('a3', 'coder:S1'),
				result('a3', { summary: 'done' }),
				started('a4', 'review:code:r0@shadow:claude-sonnet-5-5-low'),
				result('a4', 'not json'),
				started('a5', 'review:security:r0'),
			],
			factsOf: factsFrom({ a1: { model: 'claude-haiku-4.5', effort: 'low', prompt: 'P' } }),
		}
		const passes = claudePassesOf(journal)
		expect(passes.map((p) => [p.label, p.type, p.failed, p.findings?.length ?? null])).toEqual([
			['review:code:r0', 'real', false, 1],
			['review:code:r0@shadow:claude-sonnet-5-5-low', 'shadow', true, null],
			['review:security:r0', 'real', true, null],
		])
		expect(passes[0]).toMatchObject({ journal: 'wf1', kind: 'code', round: 0, model: 'claude-haiku-4.5', effort: 'low', prompt: 'P' })
		// Without a transcript, a shadow's label names its model, in the same form as everywhere else.
		expect(passes[1]).toMatchObject({ model: 'claude-sonnet-5.5', effort: 'low', prompt: null })
		expect(passes[2]).toMatchObject({ model: 'unknown', effort: 'unknown' })
	})
})

const VALIDATOR = (claim) =>
	task(
		`You are the controller validating a code-review finding.\n\nRequirements: bd-x\n\nFinding:\n[F1] serious correctness — /home/q/wt/src/lib/a.rs:12\n  Claim: ${claim}\n  Evidence: line 12 does it\n\nDECISION LEDGER: (none)`,
	)

describe('claudeValidatorsOf', () => {
	const claim = 'The lease is\nnot renewed.'
	const journal = (prompt) => ({
		wf: 'wf1',
		entries: [started('v1', 'validate:r0:F1'), result('v1', { valid: true, blocking: false, reasoning: 'r' }), started('v2', 'validate:r0:F2'), result('v2', null)],
		factsOf: factsFrom({ v1: { prompt } }),
	})

	it('reads the finding from an indented computed-task prompt and joins its verdict', () => {
		const verdicts = claudeValidatorsOf(journal(VALIDATOR(claim)))
		expect(verdicts.size).toBe(1)
		expect(verdictOf(finding('src/lib/a.rs', 12, 'The lease is not renewed.'), verdicts)).toEqual({ valid: true, blocking: false })
		expect(verdictOf(finding('src/lib/a.rs', 12, 'Another claim'), verdicts)).toBeNull()
	})

	it('reads it behind a user-request relay', () => {
		const verdicts = claudeValidatorsOf(journal(promptOf([user(RELAY), user(VALIDATOR(claim)), assistant()])))
		expect(verdictOf(finding('a.rs', 3, 'The lease is not renewed.'), verdicts)).toEqual({ valid: true, blocking: false })
	})
})

describe('handReview', () => {
	it.each([
		['review:code:r3 bd-h7oc.2 part 1 fixes', { label: 'review:code:r3', kind: 'code', round: 3, shadow: false, shadowSpec: null }],
		['review:code:r3@shadow:sonnet-medium bd-h7oc.2', { label: 'review:code:r3@shadow:sonnet-medium', kind: 'code', round: 3, shadow: true, shadowSpec: { model: 'sonnet', effort: 'medium' } }],
		['Opus review of issue 47', { label: null, kind: 'code', round: 0, shadow: false, shadowSpec: null }],
		['Shadow review h7oc.2', { label: null, kind: 'code', round: 0, shadow: true, shadowSpec: null }],
		['Re-review the fix diff', { label: null, kind: 'code', round: null, shadow: false, shadowSpec: null }],
		['Code review r2 shadow', { label: null, kind: 'code', round: 2, shadow: true, shadowSpec: null }],
		['Implement S1', null],
		['Reviewer notes', null],
		['reviewer: review:code:r1@shadow:sonnet-medium bd-x', { label: 'review:code:r1@shadow:sonnet-medium', kind: 'code', round: 1, shadow: true, shadowSpec: { model: 'sonnet', effort: 'medium' } }],
		['reviewer: security r2 bd-x', { label: null, kind: 'code', round: 2, shadow: false, shadowSpec: null }],
		['  Reviewer:  review:code:r3 bd-x', { label: 'review:code:r3', kind: 'code', round: 3, shadow: false, shadowSpec: null }],
		['coder: fix review findings', null],
		['planner: review the plan', null],
	])('%s', (description, want) => expect(handReview({ description, agentType: 'general-purpose' })).toEqual(want))

	it('is null without meta or description, and reads the description, not the prompt', () => {
		expect(handReview(null)).toBeNull()
		expect(handReview({ agentType: 'general-purpose' })).toBeNull()
		expect(handReview({ description: 'Implement S1', prompt: 'review this' })).toBeNull()
	})
})

describe('reportOf', () => {
	it('takes the last non-empty text block, or a later handback', () => {
		expect(reportOf([user('p'), said(text('first')), said(text('report'))])).toBe('report')
		expect(reportOf([user('p'), said(text('working')), said(handback('handed back'))])).toBe('handed back')
		expect(reportOf([said(handback('handed back')), said(text('final'))])).toBe('final')
		expect(reportOf([said(text('report')), said(text('  \n'), { type: 'tool_use', name: 'Bash', input: {} })])).toBe('report')
	})

	it('is null without a report', () => {
		expect(reportOf([user('p'), said({ type: 'tool_use', name: 'Bash', input: {} })])).toBeNull()
		expect(reportOf(null)).toBeNull()
	})
})

describe('findingsIn', () => {
	it.each([
		['- **serious** `crates/bd-core/src/claims.rs:12` x', [{ file: 'claims.rs', line: 12, severity: 'serious', claim: 'serious crates/bd-core/src/claims.rs:12 x' }]],
		['1. **nit** — `reviewer-catch.spec.mjs`, the wait is long', [{ file: 'reviewer-catch.spec.mjs', line: null, severity: 'nit', claim: 'nit — reviewer-catch.spec.mjs, the wait is long' }]],
		['- **minor** `.bd/playbooks/change.toml:170-171` y', [{ file: 'change.toml', line: 170, severity: 'minor', claim: 'minor .bd/playbooks/change.toml:170-171 y' }]],
	])('%s', (prose, want) => expect(findingsIn(prose)).toEqual(want))

	it('takes the severity from a heading and the file from a Where sub-bullet', () => {
		expect(findingsIn(joined('### Minor', '1. title', '   - **Where:** `src/store.rs:104-122`'))).toEqual([{ file: 'store.rs', line: 104, severity: 'minor', claim: 'title' }])
	})

	it('reads a severity-led title with its sub-bullets as one finding', () => {
		const prose = joined('**Serious: a lease is lost**', '- **Where:** `claims.rs:271`', '- **Problem:** the heartbeat races the reclaim')
		expect(findingsIn(prose)).toEqual([{ file: 'claims.rs', line: 271, severity: 'serious', claim: 'Serious: a lease is lost' }])
	})

	it.each([
		[['**Blocker:** none.', 'Checked `a.rs:3`.']],
		[['### Serious', 'None.', 'Checked a.rs:3']],
		[['### Minor', '- no blockers in a.rs']],
		[['no blockers or serious findings in a.rs']],
		[['**Blocker:** none.', '- `a.rs:3` x']],
		[['### Blockers: none', '- c.rs:1 z']],
	])('finds nothing in %j', (ls) => expect(findingsIn(joined(...ls))).toEqual([]))

	it('resets the section on a severity heading that says none', () => {
		expect(findingsIn(joined('**Blocker:** none.', '- **minor** `a.rs:3` x'))).toEqual([{ file: 'a.rs', line: 3, severity: 'minor', claim: 'minor a.rs:3 x' }])
	})

	it('does not absorb a paragraph after a blank line into a numbered item', () => {
		const prose = joined('Findings (all nits)', '1. `a.rs`, naming: x', '2. the wait is duplicated', '', 'Conventions: nothing here breaches AGENTS.md.')
		expect(findingsIn(prose)).toEqual([{ file: 'a.rs', line: null, severity: 'nit', claim: 'a.rs, naming: x' }])
	})

	it('needs a paragraph line to carry its own severity, and finds nothing in a clean report', () => {
		expect(findingsIn('One minor issue: graph.rs:5 skips the recompute.')).toEqual([{ file: 'graph.rs', line: 5, severity: 'minor', claim: 'One minor issue: graph.rs:5 skips the recompute.' }])
		expect(findingsIn(joined('All checks pass.', '', 'I verified that `src/graph.rs:12` recomputes.', 'Looks good.'))).toEqual([])
	})

	it('tells .json from .js, and is empty for a non-string report', () => {
		expect(findingsIn('- **nit** `package.json:3` and `x.js:1`')).toEqual([{ file: 'package.json', line: 3, severity: 'nit', claim: 'nit package.json:3 and x.js:1' }])
		expect(findingsIn(null)).toEqual([])
	})

	it('reads a long report quickly', () => {
		const prose = Array.from({ length: 20_000 }, (_, i) => `- **minor** \`a${i}.rs:${i}\` x`).join('\n')
		const t = performance.now()
		expect(findingsIn(prose)).toHaveLength(20_000)
		expect(performance.now() - t).toBeLessThan(1000)
	})
})

describe('namedIssues', () => {
	it('takes bd ids standing alone, never crate or repository names, paths or longer names', () => {
		expect(namedIssues('Review bd-h7oc.2 and bd-50hs.1; see bd-h7oc.2 again.')).toEqual(['bd-h7oc.2', 'bd-50hs.1'])
		expect(namedIssues('In crates/bd-core and bd-cli, bd-server, bd-sync.git, /home/q/bd-x, my-bd-y: nothing')).toEqual([])
		expect(namedIssues(null)).toEqual([])
	})
})

describe('handPromptOf', () => {
	it('takes only the first user entry before the first assistant entry', () => {
		expect(handPromptOf([apiRequest('high'), user('Review it.'), user('reminder for agent a1'), assistant()])).toBe('Review it.')
		expect(handPromptOf([assistant(), user('late')])).toBeNull()
		expect(handPromptOf(null)).toBeNull()
	})
})

const recorder = (subjects = {}) => {
	const calls = []
	const subjectOf = (sha) => {
		calls.push(sha)
		return subjects[sha] ?? null
	}
	return { calls, subjectOf }
}

describe('handIssue', () => {
	it('takes a full id in the prompt over one in the description', () => {
		expect(handIssue({ prompt: 'Review bd-a.1 now', description: 'Opus review bd-b.2', parentIds: [] })).toBe('bd-a.1')
		expect(handIssue({ prompt: 'Review it', description: 'Opus review bd-b.2', parentIds: [] })).toBe('bd-b.2')
	})

	it('does not take a crate name as an issue', () => {
		const { calls, subjectOf } = recorder()
		expect(handIssue({ prompt: 'Check crates/bd-core and bd-cli', description: 'Opus review', parentIds: [], subjectOf })).toBeNull()
		expect(calls).toEqual([])
	})

	it('maps a description shorthand to the one parent id it ends, its prefix matching', () => {
		const parentIds = ['bd-h7oc.1', 'bd-h7oc.2']
		expect(handIssue({ prompt: 'Review it', description: 'Opus re-review .2 fixes', parentIds })).toBe('bd-h7oc.2')
		expect(handIssue({ prompt: 'Review it', description: 'Shadow re-review h7oc.2', parentIds })).toBe('bd-h7oc.2')
		expect(handIssue({ prompt: 'Review it', description: 'Opus review of issue 1', parentIds })).toBe('bd-h7oc.1')
		expect(handIssue({ prompt: 'Review it', description: 'Opus re-review h7oc.2', parentIds: ['bd-abc.2', 'bd-h7oc.1'] })).toBeNull()
		expect(handIssue({ prompt: 'Review it', description: 'Opus review .2', parentIds: ['bd-h7oc.2', 'bd-qq.2'] })).toBeNull()
		expect(handIssue({ prompt: 'Review issue 1', description: 'Opus review', parentIds })).toBeNull()
	})

	it('falls back to the last id in the subject of a commit the prompt names', () => {
		const { calls, subjectOf } = recorder({ '9b62d18': 'Server-only playbook mode: playbooks.source = server (bd-h7oc.1, bd-h7oc.2)' })
		expect(handIssue({ prompt: 'Run git show 9b62d18 and review it', description: 'Opus review', parentIds: [], subjectOf })).toBe('bd-h7oc.2')
		expect(calls).toEqual(['9b62d18'])
	})

	it('never passes a hex-free, letters-only or digits-only token to subjectOf, and tries at most 5', () => {
		const { calls, subjectOf } = recorder()
		const prompt = 'defaced 1234567 deadbeefcafe zz12345ab 1a2b3c4 a1b2c3d 0000000a 1111111b 2222222c 3333333d'
		expect(handIssue({ prompt, description: 'Opus review', parentIds: [], subjectOf })).toBeNull()
		expect(calls).toEqual(['1a2b3c4', 'a1b2c3d', '0000000a', '1111111b', '2222222c'])
	})
})

const real = (over) => pass({ journal: 'hand:s:p', model: 'claude-opus-5.5', effort: 'high', issue: 'bd-x', ...over })
const shadowPass = (over) => real({ type: 'shadow', model: 'claude-sonnet-5.5', effort: 'medium', ...over })

describe('pairHandPasses', () => {
	it('pairs a real pass with each shadow over the same prompt', () => {
		const { pairs, skipped } = pairHandPasses([real({ agentId: 'r' }), shadowPass({ agentId: 's1' }), shadowPass({ agentId: 's2', model: 'claude-haiku-4.5', effort: 'low' })])
		expect(pairs.map((p) => [p.source, p.a.agentId, p.b.agentId, p.prompt])).toEqual([
			['hand-shadow', 'r', 's1', 'same'],
			['hand-shadow', 'r', 's2', 'same'],
		])
		expect(skipped).toEqual({ noShadow: 0, failed: 0 })
	})

	it('pairs nothing over different or null prompts, or at the same model and effort', () => {
		expect(pairHandPasses([real({}), shadowPass({ prompt: 'Q' })])).toEqual({ pairs: [], skipped: { noShadow: 0, failed: 0 } })
		expect(pairHandPasses([real({ prompt: null }), shadowPass({ prompt: null })])).toEqual({ pairs: [], skipped: { noShadow: 0, failed: 0 } })
		expect(pairHandPasses([real({}), shadowPass({ model: 'claude-opus-5.5', effort: 'high' })])).toEqual({ pairs: [], skipped: { noShadow: 0, failed: 0 } })
	})

	it('counts a prompt group without a shadow once in noShadow, and a failed side in failed', () => {
		expect(pairHandPasses([real({}), real({ model: 'sonnet' })]).skipped).toEqual({ noShadow: 1, failed: 0 })
		expect(pairHandPasses([real({}), shadowPass({ failed: true, findings: null })])).toEqual({ pairs: [], skipped: { noShadow: 0, failed: 1 } })
	})
})

const closed = (close_reason) => ({ status: 'closed', close_reason })
const serious = (file, line, claim = 'x') => ({ ...finding(file, line, claim), severity: 'serious' })
const bug = (file, line, claim = 'y', valid = true) => ({ file, line, claim, valid })
const findingIssue = (n, title, description) => ({ id: `bd-h.1.review.${n}`, issue_type: 'bug', status: 'closed', close_reason: 'fixed', title, description })

describe('bugVerdict', () => {
	it('is valid when closed with a fix or a commit sha', () => {
		expect(bugVerdict(closed('fixed in abc1234 by clamping the offset'))).toBe(true)
		expect(bugVerdict(closed('3dbca52'))).toBe(true)
	})

	it('is invalid when closed as not a defect, checked before a fix', () => {
		expect(bugVerdict(closed('dropped: not reproducible'))).toBe(false)
		expect(bugVerdict(closed('not a defect: the spec allows it'))).toBe(false)
		expect(bugVerdict(closed('Duplicate of bd-a.1.review.2; fixed in abc1234'))).toBe(false)
	})

	it('has no verdict for an unclear reason, an all-letter hex word, or a bug that is not closed', () => {
		expect(bugVerdict(closed('Deviations recorded on the implement step'))).toBeNull()
		expect(bugVerdict(closed('defaced'))).toBeNull()
		expect(bugVerdict({ status: 'open', close_reason: 'fixed in abc1234' })).toBeNull()
		expect(bugVerdict(null)).toBeNull()
	})
})

describe('verdictsFromBugs', () => {
	const children = [
		{ id: 'bd-h.1.review.1', issue_type: 'bug', status: 'closed', close_reason: 'fixed in abc1234', title: 'Finding F1: claims.rs:40 loses the lease', description: 'It drops it, see src/other.rs:9.' },
		{ id: 'bd-h.1.review.2', issue_type: 'bug', status: 'open', title: 'Finding: lease not renewed', description: 'The heartbeat skips it in src/lease.rs:12.' },
		{ id: 'bd-h.1.review.3', issue_type: 'bug', status: 'closed', close_reason: 'dropped', title: 'Finding F3: no file here' },
		{ id: 'bd-h.1.review.4', issue_type: 'task', status: 'closed', close_reason: 'fixed', title: 'Finding: a task' },
		{ id: 'bd-h.1.review.5', issue_type: 'bug', status: 'closed', close_reason: 'fixed', title: 'Follow-up: not a finding' },
		{ id: 'bd-h.2.review.1', issue_type: 'bug', status: 'closed', close_reason: 'fixed', title: 'Finding: another run' },
		{ id: 'bd-h.1.reviewer.1', issue_type: 'bug', status: 'closed', close_reason: 'fixed', title: 'Finding: another step' },
	]
	const stub = (answer = () => children) => {
		const calls = []
		const bd = (args) => {
			calls.push(args)
			return answer(args)
		}
		return { calls, bd }
	}

	it('keeps the Finding bugs under the run review step, with file and line from the title, else the description', () => {
		const { calls, bd } = stub()
		expect(verdictsFromBugs('bd-h.1', bd)).toEqual([
			{ file: 'claims.rs', line: 40, claim: 'claims.rs:40 loses the lease It drops it, see src/other.rs:9.', valid: true },
			{ file: 'lease.rs', line: 12, claim: 'lease not renewed The heartbeat skips it in src/lease.rs:12.', valid: null },
			{ file: null, line: null, claim: 'no file here ', valid: false },
		])
		expect(calls).toEqual([['list', '--parent', 'bd-h.1.review', '--all']])
	})

	it("takes a title file's line from a same-basename match in the description", () => {
		const { bd } = stub(() => [
			findingIssue(1, 'Finding F1: claims.rs loses the lease', 'See src/other.rs:9 and crates/bd-core/src/claims.rs:40.'),
			findingIssue(2, 'Finding F2: claims.rs:12 loses the lease', 'claims.rs:40'),
			findingIssue(3, 'Finding F3: claims.rs loses the lease', 'other.rs:9'),
		])
		expect(verdictsFromBugs('bd-h.1', bd).map(({ file, line }) => ({ file, line }))).toEqual([
			{ file: 'claims.rs', line: 40 },
			{ file: 'claims.rs', line: 12 },
			{ file: 'claims.rs', line: null },
		])
	})

	it('lists each run once per cache, and gives no bugs on a bd failure or a non-array result', () => {
		const { calls, bd } = stub()
		const cache = new Map()
		for (let i = 0; i < 3; i++) expect(verdictsFromBugs('bd-h.1', bd, cache)).toHaveLength(3)
		expect(calls).toHaveLength(1)
		const failing = stub(() => {
			throw new Error('issue not_found')
		})
		const failed = new Map()
		expect(verdictsFromBugs('bd-h.1', failing.bd, failed)).toEqual([])
		expect(verdictsFromBugs('bd-h.1', failing.bd, failed)).toEqual([])
		expect(failing.calls).toHaveLength(1)
		expect(verdictsFromBugs('bd-h.1', stub(() => ({ error: 'x' })).bd)).toEqual([])
	})

	it('never passes a run that is not a plain issue id to bd', () => {
		const { calls, bd } = stub()
		for (const run of ['x; rm -rf', 'X/../y', null, '']) expect(verdictsFromBugs(run, bd)).toEqual([])
		expect(calls).toEqual([])
	})
})

describe('matchBugs', () => {
	const LEASE = 'The lease is not renewed when the heartbeat races the reclaim'

	it('matches the same basename in different directories, lines up to 10 apart, as a validatorsOf-shaped verdict', () => {
		const f = serious('/home/q/wt/crates/bd-core/src/claims.rs', 40)
		const got = matchBugs([f], [bug('src/claims.rs', 48)])
		expect(verdictOf(f, got)).toEqual({ valid: true, blocking: false })
		expect(matchBugs([serious('a.rs', 10)], [bug('a.rs', 21)]).size).toBe(0)
		expect(matchBugs([serious('a.rs', 40)], [bug('b.rs', 40)]).size).toBe(0)
	})

	it('matches a finding naming no file to a bug that names one, on claims at least 0.3 similar', () => {
		const f = serious(null, null, LEASE)
		expect(verdictOf(f, matchBugs([f], [bug('a.rs', 40, LEASE)]))).toEqual({ valid: true, blocking: false })
		expect(matchBugs([f], [bug('a.rs', 40, 'Unrelated words entirely')]).size).toBe(0)
		expect(matchBugs([serious('', null, LEASE)], [bug('a.rs', 40, LEASE)]).size).toBe(1)
		expect(matchBugs([serious('a.rs', 40, LEASE)], [bug(null, null, LEASE)]).size).toBe(1)
	})

	it('never matches a bug naming another file on claims, and prefers a file and line match', () => {
		expect(matchBugs([serious('a.rs', 40, LEASE)], [bug('b.rs', null, LEASE)]).size).toBe(0)
		const f = serious('a.rs', 40, LEASE)
		expect(verdictOf(f, matchBugs([f], [bug(null, null, LEASE, false), bug('a.rs', 40, 'y', true)]))).toEqual({ valid: true, blocking: false })
	})

	it('gives minor and nit findings no verdict, and uses up a finding on an open bug without one', () => {
		const minor = finding('a.rs', 40, 'a minor one')
		const blocker = { ...serious('a.rs', 48, 'the blocker'), severity: 'blocker' }
		const got = matchBugs([minor, blocker], [bug('a.rs', 40, 'y', false)])
		expect(verdictOf(minor, got)).toBeNull()
		expect(verdictOf(blocker, got)).toEqual({ valid: false, blocking: false })
		const f = serious('a.rs', 40, LEASE)
		expect(matchBugs([f], [bug('a.rs', 40, 'y', null), bug(null, null, LEASE, true)]).size).toBe(0)
	})
})

describe('runBandOf', () => {
	const shown = {
		'bd-r.1': { metadata: { playbook: { role: 'run' }, score_judge: { complexity: 5, rubric: 3 } } },
		'bd-r.1.implement': { metadata: { playbook: { role: 'step', run: 'bd-r.1' } } },
		'bd-b.1': { metadata: { playbook: { role: 'run' } } },
		'bd-c': { metadata: { score: { complexity: 4, rubric: 3 } } },
		'bd-p': { metadata: {} },
		'bd-q': { metadata: {} },
		'bd-q.2': { metadata: { playbook: { role: 'run' }, complexity_estimate: { score: 4 } } },
	}
	const children = {
		'bd-p': [{ id: 'bd-p.1', metadata: { playbook: { role: 'run' }, score_judge: { complexity: 3, rubric: 2 } } }],
		'bd-q': [
			{ id: 'bd-q.1', metadata: { playbook: { role: 'step', run: 'bd-q.9' }, score_judge: { complexity: 5 } } },
			{ id: 'bd-other.1', metadata: { playbook: { role: 'run' }, score_judge: { complexity: 5 } } },
			{ id: 'bd-q.2' },
		],
	}
	const listing = () => {
		const calls = []
		const bd = (args) => {
			calls.push(args)
			if (args[0] === 'list') return children[args[2]] ?? []
			if (!(args[1] in shown)) throw new Error('issue not_found')
			return shown[args[1]]
		}
		return { calls, bd }
	}

	it('names the change run the band came from, with its rubric version', () => {
		const { bd } = listing()
		expect(runBandOf('bd-r.1', bd)).toEqual({ band: 5, source: 'judged', rubric: 3, run: 'bd-r.1' })
		expect(runBandOf('bd-r.1.implement', bd)).toEqual({ band: 5, source: 'judged', rubric: 3, run: 'bd-r.1' })
		expect(runBandOf('bd-c', bd)).toEqual({ band: 4, source: 'confirmed', rubric: 3, run: null })
		expect(runBandOf('bd-b.1', bd)).toEqual({ band: 'unknown', source: null, rubric: null, run: 'bd-b.1' })
		expect(runBandOf('bd-missing', bd)).toEqual({ band: 'unknown', source: null, rubric: null, run: null })
	})

	it('falls back to a child change run, showing a child listed without metadata and ignoring steps and other prefixes', () => {
		const { calls, bd } = listing()
		const cache = new Map()
		expect(runBandOf('bd-p', bd, cache)).toEqual({ band: 3, source: 'judged', rubric: 2, run: 'bd-p.1' })
		expect(runBandOf('bd-p', bd, cache)).toEqual({ band: 3, source: 'judged', rubric: 2, run: 'bd-p.1' })
		expect(runBandOf('bd-q', bd)).toEqual({ band: 4, source: 'estimate', rubric: null, run: 'bd-q.2' })
		expect(calls).toEqual([
			['show', 'bd-p'],
			['list', '--parent', 'bd-p', '--all'],
			['show', 'bd-q'],
			['list', '--parent', 'bd-q', '--all'],
			['show', 'bd-q.2'],
		])
	})

	it('treats a list failure or a non-array result as no children', () => {
		const failing = (args) => {
			if (args[0] === 'list') throw new Error('server unreachable')
			return { metadata: {} }
		}
		expect(bandOf('bd-p', failing)).toEqual({ band: 'unknown', source: null, rubric: null })
		expect(bandOf('bd-p', (args) => (args[0] === 'list' ? { error: 'x' } : { metadata: {} }))).toEqual({ band: 'unknown', source: null, rubric: null })
	})
})

describe('runOf with prompts', () => {
	it('takes an issue named in a Claude Code prompt when the run record has none', () => {
		expect(runOf({ issue: 'bd-a' }, ['(bd issue: bd-b)'])).toBe('bd-a')
		expect(runOf(null, [null, 'Requirements: x\n\n(bd issue: bd-b.1.implement; read it with `bd show bd-b.1.implement`)'])).toBe('bd-b.1.implement')
		expect(runOf({}, ['no issue here', null])).toBeNull()
	})
})

describe('rubricVersion', () => {
	let dir
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'reviewer-catch-rubric-'))
	})
	afterEach(() => rmSync(dir, { recursive: true, force: true }))

	it("reads the Version line of .bd/rubric.md, else null", () => {
		expect(rubricVersion(dir)).toBeNull()
		mkdirSync(join(dir, '.bd'))
		writeFileSync(join(dir, '.bd', 'rubric.md'), '# Agent work rubric\n\nVersion: 3\n\nText mentioning Version: 9 inline.\n')
		expect(rubricVersion(dir)).toBe(3)
	})
})

describe('projectDirs', () => {
	let dir
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'reviewer-catch-projects-'))
		for (const d of ['-home-q-bd-sync', '-home-q-bd-sync--claude-worktrees-wt', '-home-q-bd-syncer', '-home-q-bd-sync-other']) mkdirSync(join(dir, d))
	})
	afterEach(() => rmSync(dir, { recursive: true, force: true }))

	it('takes the main checkout and its worktrees, not a sibling with the same prefix', () => {
		expect(encodeProject('/home/q/bd-sync/.claude/worktrees/wt')).toBe('-home-q-bd-sync--claude-worktrees-wt')
		expect(projectDirs(dir, '/home/q/bd-sync').toSorted()).toEqual(['-home-q-bd-sync', '-home-q-bd-sync--claude-worktrees-wt'])
	})
})

describe('report', () => {
	const nit = (file, line, claim) => ({ ...finding(file, line, claim), severity: 'nit' })
	const rowOf = (got, model) => got.rows.validated.find((r) => r.band === 2 && r.model === model)
	const realH = () => real({ agentId: 'r', prompt: 'H', issue: 'bd-h', findings: [serious('crates/bd-core/src/claims.rs', 40, 'Lease drops on reclaim'), finding('crates/bd-core/src/claims.rs', 90, 'Real only')] })
	const shadowH = (over = {}) => shadowPass({ agentId: 's', prompt: 'H', issue: null, findings: [serious('claims.rs', 41, 'The lease is lost when reclaimed'), nit('graph.rs', 3, 'Shadow only')], ...over })
	const BUG = { id: 'bd-h.1.review.1', issue_type: 'bug', status: 'closed', close_reason: 'fixed in abc1234', title: 'Finding F1: lease is lost', description: 'claims.rs:40 drops the lease on reclaim.' }
	const bdWith = (calls, list = () => [BUG]) => (args) => {
		calls.push(args.join(' '))
		if (args[0] === 'show') return args[1] === 'bd-h' ? { metadata: {} } : undefined
		if (args[2] === 'bd-h') return [{ id: 'bd-h.1', metadata: { playbook: { role: 'run' }, score_judge: { complexity: 2, rubric: 3 } } }]
		if (args[2] === 'bd-h.1.review') return list()
		return []
	}
	const handGroup = (...passes) => ({ wf: 'hand:s:p', workflow: 'hand', args: null, passes })

	it('reads all three sources, labels each pair by its source, and merges cells of the same model across harnesses', () => {
		const copilot = {
			run: 'run1',
			workflow: 'plan-implement-review',
			args: { reviewStep: 'bd-a.1.review', issue: 'bd-a' },
			agents: [
				{ label: 'review:code:r0', model: 'claude-opus-5.5', effort: 'high', prompt: 'h1', result: { findings: [finding('a.rs', 1, 'x')] } },
				{ label: 'review:code:r0@shadow:claude-sonnet-5.5-medium', model: 'claude-sonnet-5.5', effort: 'medium', prompt: 'h1', result: { findings: [] } },
			],
		}
		const claude = {
			harness: 'claude',
			wf: 'wf_1',
			workflow: 'plan-implement-review',
			args: { issue: 'bd-b' },
			entries: [
				started('c1', 'review:code:r0'),
				result('c1', { findings: [finding('b.rs', 2, 'y')] }),
				started('c2', 'review:code:r0@shadow:claude-sonnet-5-5-medium'),
				result('c2', { findings: [finding('b.rs', 3, 'y again')] }),
			],
			factsOf: factsFrom({ c1: { model: 'claude-opus-5.5', effort: 'high', prompt: 'T' }, c2: { model: 'claude-sonnet-5.5', effort: 'medium', prompt: 'T' } }),
		}
		const issues = { 'bd-a.1': { metadata: { score_judge: { complexity: 3, rubric: 3 } } }, 'bd-b': { metadata: { score: { complexity: 3, rubric: 3 } } } }
		const got = reportFrom({ journals: [copilot], claude: [claude], hand: [], bd: (args) => issues[args[1]], currentRubric: 3 })
		expect(got.pairs.map((p) => [p.source, p.run, p.wf, p.band, p.rubric, p.prompt])).toEqual([
			['shadow', 'bd-a.1', 'run1', 3, 3, 'same'],
			['claude-shadow', 'bd-b', 'wf_1', 3, 3, 'same'],
		])
		expect(got).toMatchObject({ journals: 1, claudeJournals: 1, passes: 4, failed: 0, currentRubric: 3 })
		// One cell for opus/high against sonnet/medium, two pairs from two harnesses.
		expect(got.rows.all.filter((r) => r.model === 'claude-opus-5.5/high')).toHaveLength(1)
		expect(got.rows.all.find((r) => r.model === 'claude-opus-5.5/high')).toMatchObject({ rubric: 3, band: 3, vs: 'claude-sonnet-5.5/medium', pairs: 2, raised: 2, matched: 1, missed: 0 })
	})

	it('keeps the same band apart by rubric version', () => {
		const run = (id, issue) => ({
			run: id,
			workflow: 'plan-implement-review',
			args: { issue },
			agents: [
				{ label: 'review:code:r0', model: 'claude-opus-5.5', effort: 'high', prompt: 'h', result: { findings: [] } },
				{ label: 'review:code:r0@shadow:claude-sonnet-5.5-medium', model: 'claude-sonnet-5.5', effort: 'medium', prompt: 'h', result: { findings: [] } },
			],
		})
		const issues = { 'bd-v2': { metadata: { score_judge: { complexity: 3, rubric: 2 } } }, 'bd-v3': { metadata: { score_judge: { complexity: 3, rubric: 3 } } } }
		const got = reportFrom({ journals: [run('r2', 'bd-v2'), run('r3', 'bd-v3')], bd: (args) => issues[args[1]] })
		expect(got.rows.all.filter((r) => r.model === 'claude-opus-5.5/high').map((r) => [r.rubric, r.band, r.pairs])).toEqual([
			[2, 3, 1],
			[3, 3, 1],
		])
	})

	it('bands a hand-run pair by its own issue, and leaves one with no issue unknown without asking bd', () => {
		const calls = []
		const got = reportFrom({ hand: [{ wf: 'hand:s:main', workflow: 'hand', args: null, passes: [real({ issue: null }), shadowPass({ issue: null })] }], bd: (args) => calls.push(args) })
		expect(got.pairs.map((p) => [p.source, p.run, p.band, p.bandSource, p.rubric])).toEqual([['hand-shadow', null, 'unknown', null, null]])
		expect(calls).toEqual([])
		expect(got.handVerdicts).toBe(0)
	})

	it('gives both sides of a hand-run pair the verdict of the bug each matches under the child run review step', () => {
		const calls = []
		const got = reportFrom({ hand: [handGroup(realH(), shadowH())], bd: bdWith(calls) })
		expect(got.pairs.map((p) => [p.run, p.band, p.bandSource, p.rubric])).toEqual([['bd-h', 2, 'judged', 3]])
		expect(rowOf(got, 'claude-opus-5.5/high')).toMatchObject({ vs: 'claude-sonnet-5.5/medium', raised: 1, matched: 1, missed: 0, unverified: 1 })
		expect(rowOf(got, 'claude-sonnet-5.5/medium')).toMatchObject({ raised: 1, matched: 1, missed: 0, unverified: 1 })
		// 2, not 1: the shadow's serious finding took its own verdict from the bug, not only its partner's.
		expect(got.handVerdicts).toBe(2)
		expect(calls).toEqual(['show bd-h', 'list --parent bd-h --all', 'list --parent bd-h.1.review --all'])
	})

	it('counts a real pass that sits in two pairs once, and lists the review step once', () => {
		const calls = []
		const second = shadowH({ agentId: 's2', model: 'claude-haiku-4.5', effort: 'low', findings: [serious('claims.rs', 42, 'Lease is lost')] })
		const got = reportFrom({ hand: [handGroup(realH(), shadowH(), second)], bd: bdWith(calls) })
		expect(got.pairs).toHaveLength(2)
		expect(got.handVerdicts).toBe(3)
		expect(calls.filter((c) => c === 'list --parent bd-h.1.review --all')).toHaveLength(1)
	})

	it('prefers the real pass verdict when both passes have one for the same finding key', () => {
		const B40 = { id: 'bd-h.1.review.1', issue_type: 'bug', status: 'closed', close_reason: 'fixed in abc1234', title: 'Finding F1: claims.rs:40 drops the lease' }
		const B62 = { ...B40, id: 'bd-h.1.review.2', close_reason: 'dropped', title: 'Finding F2: claims.rs:62 drops the lease' }
		const r = real({ agentId: 'r', prompt: 'H', issue: 'bd-h', findings: [serious('crates/bd-core/src/claims.rs', 40, 'Lease drops on reclaim')] })
		const s = shadowH({ findings: [serious('claims.rs', 60, 'Lease drops on reclaim')] })
		const got = reportFrom({ hand: [handGroup(r, s)], bd: bdWith([], () => [B40, B62]) })
		// The shadow's own bug (line 62) is dropped; a shadow-last union would give raised 0, missed 0.
		expect(rowOf(got, 'claude-opus-5.5/high')).toMatchObject({ raised: 1, matched: 0, missed: 1, unverified: 0 })
		expect(got.handVerdicts).toBe(2)
	})

	it('leaves every hand finding unverified when listing the review step fails, keeping the band', () => {
		const got = reportFrom({
			hand: [handGroup(realH(), shadowH())],
			bd: bdWith([], () => {
				throw new Error('server unreachable')
			}),
		})
		expect(got.pairs.map((p) => p.band)).toEqual([2])
		expect(got.handVerdicts).toBe(0)
		expect(rowOf(got, 'claude-opus-5.5/high')).toMatchObject({ raised: 0, matched: 0, unverified: 2 })
	})
})

// One plain subagent: its meta and, unless entries is null, its transcript.
const handAgent = (dir, id, meta, entries) => {
	writeFileSync(join(dir, `agent-${id}.meta.json`), JSON.stringify(meta))
	if (entries) writeFileSync(join(dir, `agent-${id}.jsonl`), entries.map((l) => JSON.stringify(l)).join('\n'))
}
const reported = (model, t) => ({ ...assistant(model), message: { ...assistant(model).message, content: [{ type: 'text', text: t }] } })

describe('readHandPasses', () => {
	const ROOT = '/fake/bd'
	const PROMPT = 'Review the fix diff for regressions.'
	let dir
	let calls
	const subjectOf = (sha) => {
		calls.push(sha)
		return sha === '9b62d18' ? 'x (bd-h7oc.3)' : null
	}
	beforeEach(() => {
		calls = []
		dir = mkdtempSync(join(tmpdir(), 'reviewer-catch-hand-'))
		const sub = join(dir, encodeProject(ROOT), 's1', 'subagents')
		mkdirSync(join(sub, 'workflows', 'wf'), { recursive: true })
		handAgent(sub, 'p1', { agentType: 'general-purpose', description: 'coder: fix and verify' }, [user('Fix bd-h7oc.1 and bd-h7oc.2 in crates/bd-core.'), assistant()])
		handAgent(sub, 'r1', { agentType: 'general-purpose', description: 'reviewer: re-review h7oc.2 fixes', parentAgentId: 'p1', model: 'opus' }, [
			apiRequest('high'),
			user(PROMPT),
			user('reminder for agent r1'),
			reported('claude-opus-5-5', '- **serious** `crates/bd-core/src/claims.rs:12` x'),
		])
		handAgent(sub, 'sh1', { agentType: 'general-purpose', description: 'reviewer: shadow re-review h7oc.2', parentAgentId: 'p1', model: 'sonnet', effort: 'medium' }, [
			user(PROMPT),
			user('reminder for agent sh1'),
			reported('claude-sonnet-5-5', 'No findings.'),
		])
		handAgent(sub, 'o1', { agentType: 'general-purpose', description: 'reviewer: re-review h7oc.2 fixes', parentAgentId: 'p2', model: 'opus', effort: 'high' }, [user(PROMPT), reported('claude-opus-5-5', 'Clean.')])
		handAgent(sub, 'c1', { agentType: 'general-purpose', description: 'Code review r1', parentAgentId: 'p1', model: 'opus', effort: 'high' }, [user('Run git show 9b62d18 and review it.'), reported('claude-opus-5-5', 'Clean.')])
		handAgent(sub, 'n1', { agentType: 'general-purpose', description: 'coder: implement S1', parentAgentId: 'p1', model: 'opus' }, [user(PROMPT), reported('claude-opus-5-5', 'done')])
		handAgent(sub, 'f1', { agentType: 'general-purpose', description: 'reviewer: review:code:r0@shadow:claude-haiku-4-5-low bd-h7oc.1', parentAgentId: 'p1' }, null)
		handAgent(join(sub, 'workflows', 'wf'), 'w1', { agentType: 'workflow-subagent', description: 'review:code:r0' }, [user(PROMPT), reported('claude-opus-5-5', 'Clean.')])
		writeFileSync(join(sub, 'agent-..%.meta.json'), JSON.stringify({ description: 'review:code:r0' }))
	})
	afterEach(() => rmSync(dir, { recursive: true, force: true }))

	it('reads review subagents grouped by session and parent, outside workflows', () => {
		const groups = readHandPasses(dir, ROOT, { subjectOf })
		expect(groups.map((g) => [g.wf, g.workflow, g.args, g.passes.map((p) => p.agentId).toSorted()]).toSorted((x, y) => x[0].localeCompare(y[0]))).toEqual([
			['hand:s1:p1', 'hand', null, ['c1', 'f1', 'r1', 'sh1']],
			['hand:s1:p2', 'hand', null, ['o1']],
		])
		const byId = Object.fromEntries(groups.flatMap((g) => g.passes).map((p) => [p.agentId, p]))
		expect(byId.r1).toMatchObject({ journal: 'hand:s1:p1', label: null, kind: 'code', round: null, type: 'real', model: 'claude-opus-5.5', effort: 'high', prompt: PROMPT, failed: false, issue: 'bd-h7oc.2' })
		expect(byId.r1.findings).toEqual([{ file: 'claims.rs', line: 12, severity: 'serious', claim: 'serious crates/bd-core/src/claims.rs:12 x' }])
		expect(byId.sh1).toMatchObject({ type: 'shadow', model: 'claude-sonnet-5.5', effort: 'medium', prompt: PROMPT, findings: [], failed: false, issue: 'bd-h7oc.2' })
		expect(byId.o1).toMatchObject({ journal: 'hand:s1:p2', type: 'real', issue: null })
		expect(byId.c1).toMatchObject({ kind: 'code', round: 1, type: 'real', issue: 'bd-h7oc.3' })
		expect(byId.f1).toMatchObject({ label: 'review:code:r0@shadow:claude-haiku-4-5-low', type: 'shadow', model: 'claude-haiku-4.5', effort: 'low', prompt: null, findings: null, failed: true, issue: 'bd-h7oc.1' })
		for (const p of Object.values(byId)) {
			expect(p).not.toHaveProperty('description')
			expect(p).not.toHaveProperty('subject')
		}
		expect(calls).toEqual(['9b62d18'])
	})

	it('never pairs passes across parent agents', () => {
		const pairs = readHandPasses(dir, ROOT, { subjectOf }).flatMap((g) => pairHandPasses(g.passes).pairs)
		expect(pairs.map((p) => [p.a.agentId, p.b.agentId])).toEqual([['r1', 'sh1']])
	})
})

// One Claude Code workflow agent: its journal entries, meta and transcript (an optional relay, the computed task, one
// request at effort).
const workflowAgent = (dir, id, { label, model, effort, prompt, relay = false, value }) => {
	writeFileSync(join(dir, `agent-${id}.meta.json`), JSON.stringify({ agentType: 'workflow-subagent', description: label }))
	const lines = [apiRequest(effort), ...(relay ? [user(RELAY)] : []), user(task(prompt)), assistant(model)]
	writeFileSync(join(dir, `agent-${id}.jsonl`), lines.map((l) => JSON.stringify(l)).join('\n'))
	return [started(id, label), result(id, typeof value === 'string' ? value : JSON.stringify(value))]
}

describe('readClaudeJournals', () => {
	let dir
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'reviewer-catch-claude-'))
	})
	afterEach(() => rmSync(dir, { recursive: true, force: true }))

	it('reads each journal with its run record and the facts of its agents, in the main checkout and its worktrees', () => {
		const make = (project, session, wf, record) => {
			const wdir = join(dir, project, session, 'subagents', 'workflows', wf)
			mkdirSync(wdir, { recursive: true })
			mkdirSync(join(dir, project, session, 'workflows'), { recursive: true })
			if (record) writeFileSync(join(dir, project, session, 'workflows', `${wf}.json`), JSON.stringify(record))
			const entries = [{ type: 'launched' }, ...workflowAgent(wdir, 'a1', { label: 'review:code:r0', model: 'claude-opus-5-5', effort: 'high', prompt: 'Review it.', relay: true, value: { findings: [] } })]
			writeFileSync(join(wdir, 'journal.jsonl'), entries.map((e) => JSON.stringify(e)).join('\n'))
		}
		make(encodeProject('/r'), 's1', 'wf_a', { workflowName: 'plan-implement-review', args: JSON.stringify({ issue: 'bd-a', reviewStep: 'bd-a.1.review' }) })
		make(encodeProject('/r/.claude/worktrees/wt'), 's2', 'wf_b', { workflowName: 'plan-implement-review', args: 'not json' })
		make(encodeProject('/other'), 's3', 'wf_c', null)
		mkdirSync(join(dir, encodeProject('/r'), 's1', 'subagents', 'workflows', 'wf_empty'), { recursive: true })
		const got = readClaudeJournals(dir, '/r').toSorted((x, y) => x.wf.localeCompare(y.wf))
		expect(got.map((j) => [j.harness, j.wf, j.workflow, j.args])).toEqual([
			['claude', 'wf_a', 'plan-implement-review', { issue: 'bd-a', reviewStep: 'bd-a.1.review' }],
			['claude', 'wf_b', 'plan-implement-review', null],
		])
		expect(got[0].factsOf('a1')).toEqual({ model: 'claude-opus-5.5', effort: 'high', prompt: task('Review it.') })
		expect(got[0].factsOf('../x')).toEqual({ model: 'unknown', effort: 'unknown', prompt: null })
		expect(claudePassesOf(got[0])).toMatchObject([{ label: 'review:code:r0', type: 'real', model: 'claude-opus-5.5', effort: 'high', failed: false }])
	})
})

describe('reviewer-catch CLI with Claude Code and hand-run sources', () => {
	const ROOT = '/fake/bd'
	const CLAIM = 'Fixture claim the lease is lost'
	const HAND = 'Review the lease fix for bd-h.'
	let tmp
	let projects
	let sessions
	let bin

	beforeEach(() => {
		tmp = mkdtempSync(join(tmpdir(), 'reviewer-catch-claude-cli-'))
		projects = join(tmp, 'projects')
		sessions = join(tmp, 'sessions')
		bin = join(tmp, 'bin')
		mkdirSync(bin)
		mkdirSync(sessions)
		// A Claude Code plan-implement-review run with one shadow and a validator.
		const found = finding('/fake/bd/crates/bd-core/src/claims.rs', 12, CLAIM)
		const review = 'Review the diff.\n\n(bd issue: bd-a; read it)'
		const wdir = join(projects, encodeProject(ROOT), 's1', 'subagents', 'workflows', 'wf_pir')
		mkdirSync(wdir, { recursive: true })
		mkdirSync(join(projects, encodeProject(ROOT), 's1', 'workflows'), { recursive: true })
		writeFileSync(join(projects, encodeProject(ROOT), 's1', 'workflows', 'wf_pir.json'), JSON.stringify({ workflowName: 'plan-implement-review', args: JSON.stringify({ issue: 'bd-a', reviewStep: 'bd-a.1.review' }) }))
		const entries = [
			{ type: 'launched' },
			...workflowAgent(wdir, 'r0', { label: 'review:code:r0', model: 'claude-opus-5-5', effort: 'high', prompt: review, relay: true, value: { findings: [found] } }),
			...workflowAgent(wdir, 's0', { label: 'review:code:r0@shadow:claude-sonnet-5-5-medium', model: 'claude-sonnet-5-5', effort: 'medium', prompt: review, relay: true, value: { findings: [{ ...found, file: 'claims.rs', line: 14 }, finding('graph.rs', 3, 'other')] } }),
			...workflowAgent(wdir, 'v0', { label: 'validate:r0:F1', model: 'claude-opus-5-5', effort: 'high', prompt: VALIDATOR(CLAIM).replace('src/lib/a.rs', 'crates/bd-core/src/claims.rs'), value: { valid: true, blocking: true, reasoning: 'r' } }),
		]
		writeFileSync(join(wdir, 'journal.jsonl'), entries.map((e) => JSON.stringify(e)).join('\n'))
		// A hand-run real pass and its shadow, plain subagents of the main thread.
		const sub = join(projects, encodeProject(ROOT), 's2', 'subagents')
		mkdirSync(sub, { recursive: true })
		handAgent(sub, 'hr', { agentType: 'general-purpose', description: 'reviewer: lease fix', model: 'claude-opus-5-5', effort: 'high' }, [user(HAND), said(text(joined('### Serious', '1. Hand claim the lease drops', '   - Where: `crates/bd-core/src/claims.rs:40`')))])
		handAgent(sub, 'hs', { agentType: 'general-purpose', description: 'reviewer: shadow lease fix', model: 'sonnet', effort: 'medium' }, [user(HAND), said(text('Reviewing.'), handback('- **serious** `claims.rs:41` Hand claim the lease drops'))])
		// A stand-in for bd that logs every call.
		writeFileSync(
			join(bin, 'bd'),
			[
				'#!/bin/sh',
				`echo "$*" >> "${bin}/calls"`,
				'case " $* " in',
				`  *" show bd-a.1 "*) echo '${JSON.stringify({ metadata: { playbook: { role: 'run' }, score_judge: { complexity: 3, rubric: 3 } } })}' ;;`,
				`  *" show bd-h "*) echo '${JSON.stringify({ metadata: { playbook: { role: 'run' }, score: { complexity: 2, rubric: 2 } } })}' ;;`,
				`  *" list --parent bd-h.review "*) echo '${JSON.stringify([{ id: 'bd-h.review.1', issue_type: 'bug', status: 'closed', close_reason: 'fixed in abc1234', title: 'Finding F1: Bugtitle lease drops', description: 'Bugtext claims.rs:40.' }])}' ;;`,
				`  *) echo 'issue not_found' >&2; exit 3 ;;`,
				'esac',
				'',
			].join('\n'),
		)
		chmodSync(join(bin, 'bd'), 0o755)
	})
	afterEach(() => rmSync(tmp, { recursive: true, force: true }))

	const run = (...args) => {
		const script = fileURLToPath(new URL('./reviewer-catch.mjs', import.meta.url))
		try {
			return execFileSync('node', [script, '--sessions', sessions, '--projects', projects, '--root', ROOT, ...args], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, stdio: ['ignore', 'pipe', 'pipe'] })
		} catch (e) {
			throw new Error(`exit ${e.status}: ${e.stderr}`, { cause: e })
		}
	}

	it('pairs the Claude Code workflow shadow with its validator joined, and the hand-run pair validated from Finding bugs', () => {
		const got = JSON.parse(run('--json'))
		expect(got).toMatchObject({ journals: 0, claudeJournals: 1, hand: 1, passes: 2, handPasses: 2, handVerdicts: 2, currentRubric: null })
		const wf = got.pairs.find((p) => p.source === 'claude-shadow')
		expect(wf).toMatchObject({ run: 'bd-a.1', workflow: 'plan-implement-review', wf: 'wf_pir', band: 3, bandSource: 'judged', rubric: 3, prompt: 'same', matched: 1, aOnly: 0, bOnly: 1 })
		expect(wf.a).toEqual({ label: 'review:code:r0', model: 'claude-opus-5.5', effort: 'high', findings: 1 })
		expect(wf.b).toEqual({ label: 'review:code:r0@shadow:claude-sonnet-5-5-medium', model: 'claude-sonnet-5.5', effort: 'medium', findings: 2 })
		expect(got.rows.validated.find((r) => r.rubric === 3 && r.model === 'claude-opus-5.5/high')).toMatchObject({ raised: 1, matched: 1, missed: 0, unverified: 0 })
		// The hand-run shadow is known only as 'sonnet': kept apart from claude-sonnet-5.5.
		expect(got.pairs.find((p) => p.source === 'hand-shadow')).toMatchObject({ run: 'bd-h', band: 2, bandSource: 'confirmed', rubric: 2, a: { model: 'claude-opus-5.5' }, b: { model: 'sonnet' } })
		expect(got.rows.validated.find((r) => r.rubric === 2 && r.model === 'claude-opus-5.5/high')).toMatchObject({ vs: 'sonnet/medium', raised: 1, matched: 1, unverified: 0 })
		const calls = readFileSync(join(bin, 'calls'), 'utf8').trim().split('\n')
		expect(calls).toEqual([`-C ${ROOT} show bd-a.1 --json`, `-C ${ROOT} show bd-h --json`, `-C ${ROOT} list --parent bd-h.review --all --json`])
	})

	it('renders per-source counts and the rubric split, without claims, descriptions or ids', () => {
		const out = run()
		expect(out).toContain('0 Copilot workflow runs and 1 Claude Code workflow journals, 2 review passes (0 failed); 1 hand-run groups, 2 hand-run review passes (0 failed).')
		expect(out).toContain('2 pairs by source (band unknown): 0 Copilot real vs shadow (0), 1 Claude Code real vs shadow (0), 1 hand-run real vs shadow (0).')
		expect(out).toContain('| v2 | 2 | claude-opus-5.5/high | sonnet/medium | 1 | 1 | 1 | 0 | 100% | – | thin |')
		expect(out).toContain('| v3 | 3 | claude-opus-5.5/high | claude-sonnet-5.5/medium | 1 | 1 | 1 | 1 | 50% | – | thin |')
		expect(out.indexOf('| v2 |')).toBeLessThan(out.indexOf('| v3 |'))
		expect(out).not.toMatch(/Fixture claim|Hand claim|Bugtitle|Bugtext|claims\.rs|graph\.rs|bd-a|bd-h|lease fix/)
	})
})
