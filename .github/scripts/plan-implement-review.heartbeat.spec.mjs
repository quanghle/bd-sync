// renew() in .claude/workflows/plan-implement-review.js renews the lease between stages, and the Plan stage renews it
// before each planning agent through planAgent. A heartbeat agent can report a failure that isn't one (a dropped --actor
// reads as "now held by <the same actor>"), and a run that stops on it replays the cached failure on resume. So a failed
// heartbeat is escalated once, then checked against the lease bd shows, compared by the script: the same holder and
// token on a lease that has not expired (by the time the lease-check agent reports) continues; anything else, an expired
// lease included, is lost. A workflow script isn't a module (top-level await and return), so this lifts renew(),
// expired(), planAgent and what they use out of the source, like the ops and record specs, and runs them with stubs.
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
const body = [
	slice('const OPS =', '// ---------- schemas'),
	slice('const HEARTBEAT =', 'const SETUP ='),
	slice('function expired(', '// Where bd records go'),
].join('\n')
const planAgentBody = slice('// Every planning agent renews the lease first', "phase('Plan')")
const planSection = slice("phase('Plan')", '// ---------- gate')

const LEASE = { issue: 'bd-x', token: '678', actor: 'Quang Le/claude-1', root: '/repo' }

/** renew() bound to a stub agent that answers heartbeat and lease-check calls from a reply per model. */
function load({ heartbeat = {}, lease = {} }) {
	const calls = []
	const logs = []
	const agent = async (prompt, opts) => {
		calls.push({ prompt, ...opts })
		return (opts.label.includes(':lease') ? lease : heartbeat)[opts.model] ?? null
	}
	const { renew } = new Function('lease', 'TTL', 'DIR', 'agent', 'log', `${body}; return { renew }`)(LEASE, '30m', '/wt', agent, (m) =>
		logs.push(m),
	)
	return { renew, calls, logs, labels: () => calls.map((c) => c.label) }
}

const lost = { ok: false, error: 'lease lost on bd-x: now held by Quang Le/claude-1' }

describe('plan-implement-review renew()', () => {
	it('renews with one haiku call when the heartbeat succeeds', async () => {
		const { renew, calls, labels } = load({ heartbeat: { haiku: { ok: true } } })
		await renew('Plan')
		expect(labels()).toEqual(['heartbeat:0'])
		expect(calls[0].prompt).toContain('bd -C /repo heartbeat bd-x --token 678 --ttl 30m --actor "Quang Le/claude-1" --json')
		expect(calls[0]).toMatchObject({ model: 'haiku', phase: 'Plan' })
	})

	it('escalates a failed haiku heartbeat to sonnet, and stops there when sonnet renews', async () => {
		const { renew, labels } = load({ heartbeat: { haiku: lost, sonnet: { ok: true } } })
		await renew('Plan')
		expect(labels()).toEqual(['heartbeat:0', 'heartbeat:0@sonnet'])
	})

	it('continues when both heartbeats fail but bd shows the same holder and token', async () => {
		const { renew, calls, logs, labels } = load({
			heartbeat: { haiku: lost, sonnet: lost },
			lease: { haiku: { has: true, holder: 'Quang Le/claude-1', token: '678' } },
		})
		await renew('Review')
		expect(labels()).toEqual(['heartbeat:0', 'heartbeat:0@sonnet', 'heartbeat:0:lease'])
		expect(calls[2].prompt).toContain('bd -C /repo show bd-x --json')
		expect(calls[2].prompt).toContain('expires_at (as expiresAt)')
		expect(calls[2].prompt).toContain('date -u +%Y-%m-%dT%H:%M:%SZ')
		expect(logs.at(-1)).toContain('continuing')
	})

	const same = { has: true, holder: 'Quang Le/claude-1', token: '678' }

	it('stops when the lease has expired', async () => {
		const { renew } = load({
			heartbeat: { haiku: lost, sonnet: lost },
			lease: { haiku: { ...same, expiresAt: '2026-10-20T08:23:37.693Z', now: '2026-10-20T08:33:59Z' } },
		})
		await expect(renew('Gate')).rejects.toThrow('expired 2026-10-20T08:23:37.693Z')
	})

	it('stops when the lease expires within the second the check reports', async () => {
		const { renew } = load({
			heartbeat: { haiku: lost, sonnet: lost },
			lease: { haiku: { ...same, expiresAt: '2026-10-20T08:33:59.500Z', now: '2026-10-20T08:33:59Z' } },
		})
		await expect(renew('Gate')).rejects.toThrow('expired 2026-10-20T08:33:59.500Z')
	})

	it.each([
		['before expiry', { expiresAt: '2026-10-20T08:23:37.693Z', now: '2026-10-20T08:20:00Z' }],
		['with no times', {}],
		['with only expiresAt', { expiresAt: '2026-10-20T08:23:37.693Z' }],
	])('continues %s', async (_, times) => {
		const { renew, logs } = load({ heartbeat: { haiku: lost, sonnet: lost }, lease: { haiku: { ...same, ...times } } })
		await renew('Gate')
		expect(logs.at(-1)).toContain('continuing')
	})

	it.each([
		['another holder', { has: true, holder: 'Quang Le/claude-2', token: '678' }, 'held by Quang Le/claude-2'],
		['another token', { has: true, holder: 'Quang Le/claude-1', token: '701' }, 'token 701'],
		['no lease', { has: false }, 'no lease'],
	])('stops when both heartbeats fail and the lease has %s', async (_, shown, why) => {
		const { renew } = load({ heartbeat: { haiku: lost, sonnet: lost }, lease: { haiku: shown } })
		await expect(renew('Gate')).rejects.toThrow(why)
		await expect(load({ heartbeat: { haiku: lost, sonnet: lost }, lease: { haiku: shown } }).renew('Gate')).rejects.toThrow(
			'now held by Quang Le/claude-1',
		)
	})

	it('stops when the lease check fails at both levels, keeping the heartbeat error', async () => {
		const { renew, labels } = load({ heartbeat: { haiku: lost, sonnet: null } })
		await expect(renew('Fix')).rejects.toThrow(/now held by Quang Le\/claude-1.*lease check failed/)
		expect(labels()).toEqual(['heartbeat:0', 'heartbeat:0@sonnet', 'heartbeat:0:lease', 'heartbeat:0:lease@sonnet'])
	})

	it('numbers each renewal', async () => {
		const { renew, labels } = load({ heartbeat: { haiku: { ok: true } } })
		await renew('Plan')
		await renew('Gate')
		expect(labels()).toEqual(['heartbeat:0', 'heartbeat:1'])
	})
})

/** planAgent bound to stub renew and agent that record each call in events. */
function liftPlanAgent(renew, agent) {
	return new Function('renew', 'agent', `${planAgentBody}; return planAgent`)(renew, agent)
}

describe('plan-implement-review Plan-stage renewals', () => {
	const labels = ['planner:draft', 'planner:critic:0', 'planner:final:1', 'planner:revise:1']

	it.each(labels.map((l) => [l]))('renews the lease before %s and passes its options through', async (label) => {
		const events = []
		const planAgent = liftPlanAgent(
			async (phase) => events.push(['renew', phase]),
			async (prompt, opts) => (events.push(['agent', opts]), { from: opts.label, prompt }),
		)
		const result = await planAgent('the prompt', { label, effort: 'high', schema: { label } })
		expect(events).toEqual([
			['renew', 'Plan'],
			['agent', { label, effort: 'high', schema: { label }, phase: 'Plan' }],
		])
		expect(result).toEqual({ from: label, prompt: 'the prompt' })
	})

	it('does not start the planning agent once the lease is lost', async () => {
		const calls = []
		const planAgent = liftPlanAgent(
			async () => {
				throw new Error('Lost the lease on bd-x (heartbeat agent failed; no lease); stopping.')
			},
			async (prompt, opts) => calls.push(opts),
		)
		await expect(planAgent('p', { label: 'planner:critic:0', effort: 'high' })).rejects.toThrow('Lost the lease')
		expect(calls).toEqual([])
	})

	it('runs every Plan-stage agent through planAgent', () => {
		expect(planSection).not.toMatch(/\bagent\(/)
		expect(planSection).not.toMatch(/\bops\(/)
		expect(planSection).not.toMatch(/\brenew\(/)
		expect(planSection.match(/\bplanAgent\(/g)?.length).toBe(4)
		expect(planSection.split('label: ').length - 1).toBe(4)
		expect(planSection).toContain("label: 'planner:draft'")
		expect(planSection).toContain('label: `planner:critic:${rev}`')
		expect(planSection).toContain('label: `planner:final:${rev}`')
		expect(planSection).toContain('label: `planner:revise:${rev + 1}`')
	})
})
