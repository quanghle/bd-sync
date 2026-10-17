// renew() in .claude/workflows/plan-implement-review.js renews the lease between stages. A heartbeat agent can report a
// failure that isn't one (a dropped --actor reads as "now held by <the same actor>"), and a run that stops on it
// replays the cached failure on resume. So a failed heartbeat is escalated once, then checked against the lease bd shows,
// compared by the script. A workflow script isn't a module (top-level await and return), so this lifts renew() and what it
// uses out of the source, like the ops and record specs, and runs it with a stub agent.
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
	slice('let beats = 0', '// Where bd records go'),
].join('\n')

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
