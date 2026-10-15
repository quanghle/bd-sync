// ops() in .claude/workflows/plan-implement-review.js runs the mechanical agents (claim, heartbeat, bd:root, setup, gate, bd
// records) on haiku at low effort and escalates one that fails its schema once to sonnet at medium. A workflow script isn't
// a module (top-level await and return), so this lifts the helper and its constants out of the source, like the record and
// shadow specs, and runs it with a stub agent. A source check confirms every mechanical call site goes through it.
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
const body = slice('const OPS =', '// ---------- schemas')

/** ops() bound to a stub agent that records each call and answers from a reply per model. */
function load(replies) {
	const calls = []
	const logs = []
	const agent = async (prompt, opts) => {
		calls.push({ prompt, ...opts })
		return replies[opts.model]
	}
	const lifted = new Function('agent', 'log', `${body}; return { ops, OPS, OPS_ESCALATED }`)(agent, (m) => logs.push(m))
	return { ...lifted, calls, logs }
}

const SCHEMA = { type: 'object' }
const OPTS = { label: 'claim', phase: 'Setup', schema: SCHEMA }
const PROMPT = 'Run exactly: bd claim squid-x --json'
const gateValid = (r) => !!(r?.snapshot && r.passed !== r.failures.length > 0)

describe('plan-implement-review ops()', () => {
	it('names the levels by class: haiku at low, sonnet at medium', () => {
		const { OPS, OPS_ESCALATED } = load({})
		expect(OPS).toEqual({ model: 'haiku', effort: 'low' })
		expect(OPS_ESCALATED).toEqual({ model: 'sonnet', effort: 'medium' })
	})

	it('returns a valid haiku reply after one call, passing label, schema and phase through', async () => {
		const reply = { ok: true, token: 't' }
		const { ops, calls, logs } = load({ haiku: reply, sonnet: { ok: true, token: 'other' } })
		expect(await ops(PROMPT, OPTS)).toBe(reply)
		expect(calls).toEqual([{ prompt: PROMPT, label: 'claim', phase: 'Setup', schema: SCHEMA, model: 'haiku', effort: 'low' }])
		expect(logs).toEqual([])
	})

	it('escalates a null haiku reply once to sonnet at medium, labelled @sonnet', async () => {
		const reply = { ok: true, token: 't' }
		const { ops, calls, logs } = load({ haiku: null, sonnet: reply })
		expect(await ops(PROMPT, OPTS)).toBe(reply)
		expect(calls).toHaveLength(2)
		expect(calls[0]).toMatchObject({ model: 'haiku', effort: 'low', label: 'claim' })
		const [, again] = calls
		expect(again).toMatchObject({ model: 'sonnet', effort: 'medium', label: 'claim@sonnet', phase: 'Setup', schema: SCHEMA })
		expect(again.prompt.startsWith(PROMPT)).toBe(true)
		expect(again.prompt).toContain('An earlier attempt')
		expect(logs).toHaveLength(1)
		expect(logs[0]).toContain('claim')
		expect(logs[0]).toContain('haiku')
		expect(logs[0]).toContain('sonnet')
	})

	it('returns null after exactly two calls when both levels fail', async () => {
		const { ops, calls } = load({ haiku: null, sonnet: null })
		expect(await ops(PROMPT, OPTS)).toBeNull()
		expect(calls.map((c) => c.model)).toEqual(['haiku', 'sonnet'])
	})

	it('does not escalate a valid report of a real failure (ok=false)', async () => {
		const reply = { ok: false, error: 'held' }
		const { ops, calls, logs } = load({ haiku: reply, sonnet: { ok: true } })
		expect(await ops(PROMPT, OPTS)).toBe(reply)
		expect(calls).toHaveLength(1)
		expect(logs).toEqual([])
	})

	it('escalates a gate report that contradicts itself, and returns null if sonnet contradicts itself too', async () => {
		const contradictory = { snapshot: 's', passed: true, failures: [{ command: 'lint' }] }
		const consistent = { snapshot: 's2', passed: false, failures: [{ command: 'lint' }] }
		const gate = { label: 'gate:impl', phase: 'Gate', schema: SCHEMA }

		const fixed = load({ haiku: contradictory, sonnet: consistent })
		expect(await fixed.ops(PROMPT, gate, gateValid)).toBe(consistent)
		expect(fixed.calls.map((c) => [c.model, c.label])).toEqual([
			['haiku', 'gate:impl'],
			['sonnet', 'gate:impl@sonnet'],
		])

		const broken = load({ haiku: contradictory, sonnet: contradictory })
		expect(await broken.ops(PROMPT, gate, gateValid)).toBeNull()
		expect(broken.calls).toHaveLength(2)
	})

	it('does not escalate a consistent failed gate (passed=false with failures)', async () => {
		const failed = { snapshot: 's', passed: false, failures: [{ command: 'test' }] }
		const { ops, calls } = load({ haiku: failed, sonnet: null })
		expect(await ops(PROMPT, { label: 'gate:impl', phase: 'Gate', schema: SCHEMA }, gateValid)).toBe(failed)
		expect(calls).toHaveLength(1)
	})
})

describe('plan-implement-review mechanical call sites', () => {
	const lastCall = (name, before) => {
		let at = -1
		for (const m of source.slice(0, before).matchAll(new RegExp(`\\b${name}\\(`, 'g'))) at = m.index
		return at
	}

	it.each([`label: 'claim'`, '{ label, phase, schema: HEARTBEAT }', 'label: `${label}:lease`', `label: 'bd:root'`, `label: 'setup'`, `phase: 'Gate', schema: GATE`, 'label: `record:r'])(
		'%s appears once and goes through ops(), not agent()',
		(marker) => {
			const i = source.indexOf(marker)
			expect(i).toBeGreaterThan(-1)
			expect(source.indexOf(marker, i + 1)).toBe(-1)
			expect(lastCall('ops', i)).toBeGreaterThan(lastCall('agent', i))
		},
	)

	it('sets low effort only in the OPS constant', () => {
		const lows = [...source.matchAll(/effort: 'low'/g)].map((m) => m.index)
		expect(lows).toHaveLength(1)
		expect(source.lastIndexOf('const OPS =', lows[0])).toBe(source.indexOf('const OPS ='))
		expect(lows[0] - source.indexOf('const OPS =')).toBeLessThan(60)
	})
})
