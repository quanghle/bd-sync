// The fix loop in .claude/workflows/plan-implement-review.js settles one ledger entry per change the fix coder reports, and
// a change counts only when its id is one of that call's F-ids: the coder:fix schema (fixedSchema) restricts changes[].id
// to them, and matchFixes matches on the F-id alone. A change once reported under a bd id (an unrelated issue's, or the
// finding's own bdId) settled a bogus ledger entry, with the files the coder changed standing in for the finding's.
// A workflow script isn't a module (top-level await and return), so this lifts FIXED and the two helpers out of the
// source, like the ops, record and logs specs, and source checks confirm the Fix phase uses them.
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

const { FIXED, fixedSchema, matchFixes } = new Function(
	`${slice('const CODER =', 'const TRIAGE =')}\n${slice('const fixedSchema =', 'for (let round = 0')}; return { FIXED, fixedSchema, matchFixes }`,
)()

const F1 = { id: 'F1', bdId: 'bd-x.review.1', file: 'src/a.rs', claim: 'c1' }
const F2 = { id: 'F2', file: 'src/b.rs', claim: 'c2' }
const UNRELATED = 'bd-nx85b'
const item = (f) => ({ f, d: { action: 'fix' } })
const accepts = (s, id) => s.properties.changes.items.properties.id.enum.includes(id)

describe('plan-implement-review matchFixes()', () => {
	it('matches a change to its finding by F-id', () => {
		const ch = { id: 'F1', change: 'x' }
		expect(matchFixes([item(F1)], [ch])).toEqual({ matched: [{ f: F1, ch }], unmatched: [], skipped: [] })
	})

	it('skips a finding no change names', () => {
		const ch = { id: 'F1', change: 'x' }
		const w2 = item(F2)
		const { matched, unmatched, skipped } = matchFixes([item(F1), w2], [ch])
		expect(matched).toEqual([{ f: F1, ch }])
		expect(unmatched).toEqual([])
		expect(skipped).toEqual([w2])
	})

	it('settles nothing for an unrelated id and skips the finding', () => {
		const w1 = item(F1)
		const { matched, unmatched, skipped } = matchFixes([w1], [{ id: UNRELATED, change: 'x' }])
		expect(matched).toEqual([])
		expect(unmatched).toEqual([UNRELATED])
		expect(skipped).toEqual([w1])
	})

	it("treats a change reported under the finding's bd id only as unmatched", () => {
		const w1 = item(F1)
		const { matched, unmatched, skipped } = matchFixes([w1], [{ id: F1.bdId, change: 'x' }])
		expect(matched).toEqual([])
		expect(unmatched).toEqual([F1.bdId])
		expect(skipped).toEqual([w1])
	})

	it('skips every finding when the coder returns no changes', () => {
		const work = [item(F1), item(F2)]
		expect(matchFixes(work, undefined)).toEqual({ matched: [], unmatched: [], skipped: work })
	})
})

describe('plan-implement-review fixedSchema()', () => {
	it("limits changes[].id to the call's F-ids and leaves FIXED unchanged", () => {
		const before = structuredClone(FIXED)
		const s = fixedSchema([item(F1), item(F2)])
		const id = s.properties.changes.items.properties.id
		expect(id.type).toBe('string')
		expect(id.enum).toEqual(['F1', 'F2'])
		expect(accepts(s, 'F1')).toBe(true)
		expect(accepts(s, UNRELATED)).toBe(false)
		expect(accepts(s, F1.bdId)).toBe(false)

		expect(FIXED).toEqual(before)
		expect(FIXED.properties.changes.items.properties.id).toEqual({ type: 'string' })
		expect(s.required).toEqual(FIXED.required)
		for (const key of ['summary', 'filesChanged', 'notes']) expect(s.properties[key]).toEqual(FIXED.properties[key])
		expect(s.properties.changes.items.required).toEqual(FIXED.properties.changes.items.required)
		expect(s.properties.changes.items.properties.change).toEqual(FIXED.properties.changes.items.properties.change)
	})
})

describe('plan-implement-review Fix phase source', () => {
	it('asks the coder for the F-id', () => {
		expect(slice('const fixPrompt =', 'const fixedSchema =')).toContain('F-id exactly as given')
	})

	it('passes the per-call schema and matches changes by F-id only', () => {
		const fix = slice("phase('Fix')", 'open = work.map')
		expect(fix).toContain('schema: fixedSchema(work)')
		expect(fix).toContain('matchFixes(work, fixed.changes)')
		expect(fix).not.toContain('schema: FIXED')
		expect(fix).not.toContain('fixedIds')
		expect(source).not.toContain('findingOf')
		expect(source).not.toContain('bdId ===')
		const reason = fix.slice(fix.indexOf('reason:'), fix.indexOf('notes: fixed.notes'))
		expect(reason).toContain('without breaking the ledger')
		expect(reason).toContain('unmatched.join(')
	})
})
