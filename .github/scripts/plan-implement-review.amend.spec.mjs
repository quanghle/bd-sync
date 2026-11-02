// Triage in .claude/workflows/plan-implement-review.js may amend settled ledger decisions, and guardAmendments is what the
// planner cannot talk its way past: it refuses an amendment (rewriting it to escalate) before anything applies, so a
// refusal leaves the ledger and the amendment count untouched. An unknown id among known ones once crashed the apply loop,
// and an answer could cross the amendment budget or supersede one entry twice, because the guard checked each amendment
// alone. A workflow script isn't a module (top-level await and return), so this lifts the helper out of the source, like
// the fix spec, and source checks confirm the triage step runs it before the escalate check and the apply loop.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from './expect.mjs'

const source = readFileSync(fileURLToPath(new URL('../../.claude/workflows/plan-implement-review.js', import.meta.url)), 'utf8')
const slice = (from, to) => {
	const i = source.indexOf(from)
	const j = source.indexOf(to, i)
	if (i < 0 || j < 0) throw new Error(`plan-implement-review.js no longer has ${from} … ${to}`)
	return source.slice(i, j)
}

const { guardAmendments } = new Function(`${slice('const guardAmendments =', 'for (let round = 0')}; return { guardAmendments }`)()

const ledger = () => [
	{ id: 'D1', source: 'plan', decision: 'one' },
	{ id: 'D2', source: 'plan', decision: 'two' },
	{ id: 'D3', source: 'plan', decision: 'three', supersededBy: 'D4' },
	{ id: 'D4', source: 'amend', decision: 'four' },
	{ id: 'D5', source: 'plan', decision: 'five' },
]
const amend = (id, ...supersedes) => ({ f: { id }, d: { action: 'amend', reason: 'r', supersedes } })
// Runs the guard over an answer, and checks it left the ledger alone whatever it decided.
const guard = (decided, used = 0, max = 2) => {
	const l = ledger()
	const before = structuredClone(l)
	expect(guardAmendments(decided, l, used, max)).toBeUndefined()
	expect(l).toEqual(before)
	return decided
}
const kept = (x) => expect(x.d.action).toBe('amend')
const refused = (x, why) => {
	expect(x.d.action).toBe('escalate')
	expect(x.d.reason).toBe(`r [guard: ${why}]`)
}

describe('plan-implement-review guardAmendments()', () => {
	it.each([[['D1', 'D99']], [['D99']]])('refuses an unknown id: %j', (ids) => {
		const [x] = guard([amend('F1', ...ids)])
		refused(x, 'D99 not in the ledger')
	})

	it('names every unknown id', () => {
		const [x] = guard([amend('F1', 'D98', 'D1', 'D99')])
		refused(x, 'D98, D99 not in the ledger')
	})

	it('refuses the amendment that crosses the budget', () => {
		const [a, b] = guard([amend('F1', 'D1'), amend('F2', 'D2')], 1, 2)
		kept(a)
		refused(b, 'amendment budget (2) spent')
	})

	it('leaves an answer landing exactly on the budget', () => {
		const [a, b] = guard([amend('F1', 'D1'), amend('F2', 'D2')], 0, 2)
		kept(a)
		kept(b)
	})

	it('counts an amendment of two entries as one', () => {
		const [a, b] = guard([amend('F1', 'D1', 'D2'), amend('F2', 'D5')], 1, 3)
		kept(a)
		kept(b)
	})

	it('refuses a second amendment of one entry', () => {
		const [a, b] = guard([amend('F1', 'D1'), amend('F2', 'D1')])
		kept(a)
		refused(b, 'D1 already superseded')
	})

	it('refuses an amendment overlapping an earlier one', () => {
		const [a, b] = guard([amend('F1', 'D1', 'D2'), amend('F2', 'D2')], 0, 3)
		kept(a)
		refused(b, 'D2 already superseded')
	})

	it('a refused amendment marks no entries', () => {
		const [a, b] = guard([amend('F1', 'D1', 'D99'), amend('F2', 'D1')], 1, 2)
		refused(a, 'D99 not in the ledger')
		kept(b)
	})

	it('a refused amendment takes no budget', () => {
		const [a, b] = guard([amend('F1', 'D99'), amend('F2', 'D1')], 1, 2)
		refused(a, 'D99 not in the ledger')
		kept(b)
	})

	it('allows an id repeated inside one amendment', () => {
		const [x] = guard([amend('F1', 'D1', 'D1')])
		kept(x)
	})

	it('refuses an amendment naming no entry', () => {
		const [empty] = guard([amend('F1')])
		refused(empty, 'amend names no ledger entry')
		const missing = { f: { id: 'F1' }, d: { action: 'amend', reason: 'r' } }
		guard([missing])
		refused(missing, 'amend names no ledger entry')
	})

	it('refuses an entry superseded in an earlier round', () => {
		const [x] = guard([amend('F1', 'D3')])
		refused(x, 'D3 already superseded')
	})

	it('refuses overturning an amendment', () => {
		const [x] = guard([amend('F1', 'D4')])
		refused(x, 'would overturn an amendment (D4): flip-flop')
	})

	it('refuses an amendment when earlier rounds spent the budget', () => {
		const [x] = guard([amend('F1', 'D1')], 2, 2)
		refused(x, 'amendment budget (2) spent')
	})

	it('keeps the very object of a valid amendment', () => {
		const x = amend('F1', 'D1')
		const d = x.d
		guard([x])
		expect(x.d).toBe(d)
	})

	it.each([
		[0, 2],
		[2, 2],
	])('leaves other actions alone (used %d of %d)', (used, max) => {
		const decided = [
			{ f: { id: 'F1' }, d: { action: 'fix', reason: 'r', instruction: 'i' } },
			{ f: { id: 'F2' }, d: { action: 'drop', reason: 'r' } },
			{ f: { id: 'F3' }, d: { action: 'escalate', reason: 'r' } },
		]
		const ds = decided.map((x) => x.d)
		const before = structuredClone(decided)
		guard(decided, used, max)
		expect(decided).toEqual(before)
		decided.forEach((x, i) => expect(x.d).toBe(ds[i]))
	})

	it('puts an unknown id before an entry already superseded', () => {
		const [x] = guard([amend('F1', 'D3', 'D99')])
		refused(x, 'D99 not in the ledger')
	})

	it('puts an entry already superseded before overturning an amendment', () => {
		const [x] = guard([amend('F1', 'D3', 'D4')])
		refused(x, 'D3 already superseded')
	})

	it('puts overturning an amendment before the budget', () => {
		const [x] = guard([amend('F1', 'D4')], 2, 2)
		refused(x, 'would overturn an amendment (D4): flip-flop')
	})
})

describe('plan-implement-review triage source', () => {
	const loop = source.slice(source.indexOf('for (let round = 0'))

	it('guards the whole answer before the escalate check and the apply loop', () => {
		const guarded = loop.indexOf('guardAmendments(decided, ledger, amendments, MAX_AMENDMENTS)')
		expect(guarded).toBeGreaterThan(-1)
		expect(guarded).toBeLessThan(loop.indexOf('const escalate = decided.filter'))
		expect(loop.indexOf('const escalate = decided.filter')).toBeLessThan(loop.indexOf('amendments++'))
	})

	it('has no inline guard left', () => {
		expect(loop).not.toContain('already superseded')
	})
})
