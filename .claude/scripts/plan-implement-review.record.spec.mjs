// record() and noteSettled() in .claude/workflows/plan-implement-review.js: the commands record() hands the record agent,
// and the findings reviewers are told are already decided. A workflow script isn't a module (top-level await and return),
// so this lifts them and what they use (ops(), which record() calls agent through) out of the source and runs record() with a
// stub agent that captures the prompt.
import { execFileSync } from 'node:child_process'
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
const body = [
	slice('const OPS =', '// ---------- schemas'),
	slice('const RECORD =', 'const PLAN ='),
	slice('const fmtFinding =', 'const fmtPlan ='),
	slice('const confirmedFixes = []', '// Rejected findings'),
].join('\n')

/** record() bound to a stub agent that answers with reply and keeps the prompt. */
function load(reply) {
	const seen = { prompt: '', logs: [] }
	const agent = async (prompt) => ((seen.prompt = prompt), reply)
	const { record } = new Function('A', 'g', 'DIR', 'bdFlags', 'agent', 'log', `${body}; return { record }`)(
		{ reviewStep: 'squid-x.1.review' },
		{ snapshot: 'abcdef1234' },
		'/w',
		() => '',
		agent,
		(m) => seen.logs.push(m),
	)
	return { record, seen }
}
const finding = (claim, id = 'F1') => ({ id, severity: 'minor', category: 'c', file: 'a.ts', line: 3, claim, evidence: 'e' })
const titleWord = (prompt, kind) => {
	const line = prompt.split('\n').find((l) => l.startsWith(`${kind}: bd create `))
	return line.slice(`${kind}: bd create `.length, line.indexOf(' -t '))
}
const shell = (word) => execFileSync('sh', ['-c', `printf '%s' ${word}`], { encoding: 'utf8' })

describe('plan-implement-review record()', () => {
	it.each([
		['command substitution and variables', 'Uses `$props()` and $(touch /tmp/squid-pwned) with $HOME!'],
		['quotes', `it's "quoted"`],
		['line breaks', 'spans\nlines\tand tabs'],
	])('passes a title with %s to bd unchanged', async (_, claim) => {
		const { record, seen } = load({ ok: true, filed: [{ id: 'F1', bdId: 'squid-a' }], followedUp: [{ id: 'F1', bdId: 'squid-b' }] })
		await record(0, { file: [finding(claim)], followUps: [finding(claim)] })
		const oneLine = claim.replace(/\s+/g, ' ')
		expect(shell(titleWord(seen.prompt, 'FILE F1'))).toBe(`Finding F1: ${oneLine}`)
		expect(shell(titleWord(seen.prompt, 'FOLLOW-UP F1'))).toBe(oneLine)
	})

	it('cuts a title at 200 characters', async () => {
		const { record, seen } = load({ ok: true, filed: [], followedUp: [{ id: 'F1', bdId: 'squid-b' }] })
		await record(0, { followUps: [finding('x'.repeat(250))] })
		expect(shell(titleWord(seen.prompt, 'FOLLOW-UP F1'))).toHaveLength(200)
	})

	it('labels each follow-up with a key that a rerun finds, and records the filed ids', async () => {
		const { record, seen } = load({ ok: true, filed: [], followedUp: [{ id: 'F1', bdId: 'squid-a' }] })
		const a = finding('A claim')
		await record(0, { followUps: [a] })
		const label = /-l (followup:squid-x\.1\.review\/[0-9a-f]{8}) /.exec(seen.prompt)?.[1]
		expect(label).toBeTruthy()
		expect(seen.prompt).toContain('before each FOLLOW-UP, with `bd list --all -l <its followup: label> --json`')
		expect(a.bdId).toBe('squid-a')
		// The key follows the finding's file and claim, not its id, which restarts at F1 every run.
		const again = load({ ok: true, filed: [], followedUp: [{ id: 'F9', bdId: 'squid-a' }] })
		await again.record(0, { followUps: [finding('A claim', 'F9')] })
		expect(again.seen.prompt).toContain(`-l ${label} `)
	})

	it('logs a follow-up the agent did not confirm instead of stopping the run', async () => {
		const { record, seen } = load({ ok: true, filed: [] })
		await expect(record(0, { followUps: [finding('A claim')] })).resolves.toBeUndefined()
		expect(seen.logs).toEqual(['Round 0: follow-ups not confirmed filed on squid-x.1.review: F1'])
		await expect(load({ ok: false, error: 'bd down' }).record(0, { followUps: [finding('A claim')] })).rejects.toThrow('Could not record review round 0')
	})
})

describe('plan-implement-review noteSettled()', () => {
	const load = () => new Function(`${slice('const settledFindings = []', 'const ledgerBlock =')}; return { noteSettled, fmtSettled }`)()
	const v = (id, valid, blocking, severity = 'minor') => ({ ...finding(`claim ${id}`, id), valid, blocking, severity, reasoning: `why ${id}` })

	it('lists rejected findings and valid ones left out of the change, so a reworded repeat is refused', () => {
		const { noteSettled, fmtSettled } = load()
		expect(fmtSettled()).toBe('(none)')
		noteSettled([v('F1', false, false), v('F2', true, false), v('F3', true, false, 'nit'), v('F4', true, true, 'serious')])
		expect(fmtSettled().split('\n')).toEqual([
			'- [F1] a.ts: claim F1 — rejected: why F1',
			'- [F2] a.ts: claim F2 — filed as a follow-up: valid but not blocking; left out of this change',
			'- [F3] a.ts: claim F3 — noted as a nit: valid but not blocking; left out of this change',
		])
	})
})
