// args.shadowReview in .claude/workflows/plan-implement-review.js: shadowsOf() checks it, and review() runs each real
// reviewer once more per shadow with the same prompt, keeping shadow results out of what it returns. A workflow script isn't
// a module (top-level await and return), so this lifts them and what they use out of the source, like the record spec,
// and runs review() with stub agent and parallel functions.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from './expect.mjs'

const source = readFileSync(fileURLToPath(new URL('../workflows/plan-implement-review.js', import.meta.url)), 'utf8')
const slice = (from, to) => {
	const i = source.indexOf(from)
	const j = source.indexOf(to, i)
	if (i < 0 || j < 0) throw new Error(`plan-implement-review.js no longer has ${from} … ${to}`)
	return source.slice(i, j)
}
const shadowsBody = slice('const EFFORTS =', 'const SHADOWS =')
const reviewBody = [
	slice('const fmtFinding =', 'const fmtDecisions ='),
	slice('const touchesEngine =', 'const dedupe ='),
	slice('async function review(', '// Controller:'),
].join('\n')

const { shadowsOf } = new Function(`${shadowsBody}; return { shadowsOf }`)()

const parallel = (thunks) => Promise.all(thunks.map((t) => t()))

/** review() bound to stubs: agent records each call and answers with a finding marked by its label (or null for fail). */
function load(SHADOWS, { fail = () => false } = {}) {
	const calls = []
	const shadowFindings = []
	const agent = async (prompt, opts) => {
		calls.push({ prompt, label: opts.label, model: opts.model, effort: opts.effort, agentType: opts.agentType })
		return fail(opts.label) ? null : { findings: [{ file: 'a.ts', line: 1, claim: `from ${opts.label}` }], resolved: [] }
	}
	const plan = { summary: 's', requirements: [{ id: 'R1' }], steps: [], decisions: [] }
	const { review } = new Function(
		'agent',
		'parallel',
		'SHADOWS',
		'shadowFindings',
		'TASK',
		'plan',
		'setup',
		'DIR',
		'A',
		'ledgerBlock',
		'REVIEW',
		`${reviewBody}; return { review }`,
	)(agent, parallel, SHADOWS, shadowFindings, 'Requirements:\nR1', plan, { baseline: 'base0' }, '/w', {}, () => 'LEDGER', {})
	return { review, calls, shadowFindings }
}
const approved = [{ id: 'F1', severity: 'serious', category: 'c', file: 'a.ts', line: 3, claim: 'c', evidence: 'e' }]
const SONNET = [{ model: 'sonnet', effort: 'medium' }]

describe('plan-implement-review shadowsOf()', () => {
	it('returns no shadows without the arg', () => {
		expect(shadowsOf(undefined)).toEqual([])
		expect(shadowsOf(null)).toEqual([])
	})

	it('accepts one object or an array of them', () => {
		expect(shadowsOf({ model: 'sonnet', effort: 'medium' })).toEqual(SONNET)
		expect(
			shadowsOf([
				{ model: 'sonnet', effort: 'medium' },
				{ model: 'claude-haiku-4.5', effort: 'low' },
			]),
		).toEqual([...SONNET, { model: 'claude-haiku-4.5', effort: 'low' }])
	})

	it.each([
		['a missing effort', { model: 'sonnet' }],
		['an unknown effort', { model: 'sonnet', effort: 'huge' }],
		['a model with a colon', { model: 'a:b', effort: 'low' }],
		['a model with a space', { model: 'a b', effort: 'low' }],
		['an empty array', []],
		['a string', 'sonnet'],
	])('throws on %s', (_, v) => {
		expect(() => shadowsOf(v)).toThrow(/args\.shadowReview must be \{ model, effort \} or an array of them \(effort: low\|medium\|high\|xhigh\|max\), got /)
	})
})

describe('plan-implement-review review() with shadowReview', () => {
	it('runs only the real reviewers without shadows', async () => {
		const { review, calls, shadowFindings } = load([])
		const out = await review(0, 'snap1', ['README.md'], 'base0', [])
		expect(calls.map((c) => c.label)).toEqual(['review:code:r0', 'review:requirements:r0'])
		expect(calls.every((c) => c.model === undefined && c.effort === undefined)).toBe(true)
		expect(out).toHaveLength(2)
		expect(shadowFindings).toEqual([])
	})

	it('runs each reviewer once more per shadow with the same prompt and returns only the real results', async () => {
		const { review, calls, shadowFindings } = load(SONNET)
		const out = await review(0, 'snap1', ['README.md'], 'base0', [])
		expect(calls.map((c) => c.label)).toEqual([
			'review:code:r0',
			'review:requirements:r0',
			'review:code:r0@shadow:sonnet-medium',
			'review:requirements:r0@shadow:sonnet-medium',
		])
		const [code, reqs, shadowCode, shadowReqs] = calls
		expect(shadowCode.prompt).toBe(code.prompt)
		expect(shadowReqs.prompt).toBe(reqs.prompt)
		expect([code.model, code.effort, reqs.model, reqs.effort]).toEqual([undefined, undefined, undefined, undefined])
		expect([shadowCode.model, shadowCode.effort]).toEqual(['sonnet', 'medium'])
		expect(out.map((r) => r.findings[0].claim)).toEqual(['from review:code:r0', 'from review:requirements:r0'])
		expect(shadowFindings).toEqual([
			{
				round: 0,
				kind: 'code',
				model: 'sonnet',
				effort: 'medium',
				label: 'review:code:r0@shadow:sonnet-medium',
				findings: [{ file: 'a.ts', line: 1, claim: 'from review:code:r0@shadow:sonnet-medium' }],
			},
			{
				round: 0,
				kind: 'requirements',
				model: 'sonnet',
				effort: 'medium',
				label: 'review:requirements:r0@shadow:sonnet-medium',
				findings: [{ file: 'a.ts', line: 1, claim: 'from review:requirements:r0@shadow:sonnet-medium' }],
			},
		])
	})

	it('shadows the reviewers a diff adds, with the same prompt', async () => {
		const { review, calls } = load(SONNET)
		await review(0, 'snap1', ['crates/bd-core/src/ready.rs', 'crates/bd-server/src/serve/mod.rs'], 'base0', [])
		const added = calls.filter((c) => /^review:(invariants|security):/.test(c.label))
		expect(added.map((c) => [c.label, c.model])).toEqual([
			['review:invariants:r0', undefined],
			['review:security:r0', undefined],
			['review:invariants:r0@shadow:sonnet-medium', 'sonnet'],
			['review:security:r0@shadow:sonnet-medium', 'sonnet'],
		])
		expect(added[2].prompt).toBe(added[0].prompt)
		expect(added[3].prompt).toBe(added[1].prompt)
	})

	it('shadows a focused re-review too, once per shadow', async () => {
		const shadows = [...SONNET, { model: 'haiku', effort: 'low' }]
		const { review, calls, shadowFindings } = load(shadows)
		const out = await review(1, 'snap2', ['README.md'], 'snap1', approved)
		expect(calls.map((c) => c.label)).toEqual(['review:code:r1', 'review:code:r1@shadow:sonnet-medium', 'review:code:r1@shadow:haiku-low'])
		expect(calls[0].prompt).toContain('FOCUSED RE-REVIEW')
		expect(new Set(calls.map((c) => c.prompt)).size).toBe(1)
		expect(out).toHaveLength(1)
		expect(shadowFindings.map((s) => [s.round, s.kind, s.model, s.effort])).toEqual([
			[1, 'code', 'sonnet', 'medium'],
			[1, 'code', 'haiku', 'low'],
		])
	})

	it('records a failed shadow as findings null and leaves the real results alone', async () => {
		const { review, shadowFindings } = load(SONNET, { fail: (label) => label === 'review:code:r0@shadow:sonnet-medium' })
		const out = await review(0, 'snap1', ['README.md'], 'base0', [])
		expect(out.map((r) => r.findings[0].claim)).toEqual(['from review:code:r0', 'from review:requirements:r0'])
		expect(shadowFindings.map((s) => [s.label, s.findings === null])).toEqual([
			['review:code:r0@shadow:sonnet-medium', true],
			['review:requirements:r0@shadow:sonnet-medium', false],
		])
	})

	it('passes a failed real reviewer through as null for the caller to filter', async () => {
		const { review } = load(SONNET, { fail: (label) => label === 'review:code:r0' })
		const out = await review(0, 'snap1', ['README.md'], 'base0', [])
		expect(out[0]).toBeNull()
		expect(out.filter(Boolean)).toHaveLength(1)
	})
})
