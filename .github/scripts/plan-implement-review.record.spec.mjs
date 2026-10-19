// record() and noteSettled() in .claude/workflows/plan-implement-review.js: the commands record() hands the record agent,
// and the findings reviewers are told are already decided. A workflow script isn't a module (top-level await and return),
// so this lifts them and what they use (ops(), which record() calls agent through) out of the source and runs record() with a
// stub agent that captures the prompt.
import { execFileSync } from 'node:child_process'
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
	slice('const RECORD =', 'const PLAN ='),
	slice('const fmtFinding =', 'const fmtPlan ='),
	slice('const confirmedFixes = []', '// Rejected findings'),
].join('\n')

/**
 * record() bound to a stub agent that keeps each call's label and prompt. It answers with reply on every call, or, when reply
 * is an array, with one element per call, the last repeating.
 */
function load(reply) {
	const seen = { prompt: '', logs: [], calls: [] }
	const agent = async (prompt, opts) => {
		seen.prompt = prompt
		seen.calls.push({ label: opts.label, prompt })
		return Array.isArray(reply) ? reply[Math.min(seen.calls.length - 1, reply.length - 1)] : reply
	}
	const { record, confirmedFixes } = new Function('A', 'g', 'DIR', 'bdFlags', 'agent', 'log', `${body}; return { record, confirmedFixes }`)(
		{ reviewStep: 'bd-x.1.review' },
		{ snapshot: 'abcdef1234' },
		'/w',
		() => '',
		agent,
		(m) => seen.logs.push(m),
	)
	return { record, seen, confirmedFixes }
}
const finding = (claim, id = 'F1') => ({ id, severity: 'minor', category: 'c', file: 'a.rs', line: 3, claim, evidence: 'e' })
const titleWord = (prompt, kind) => {
	const line = prompt.split('\n').find((l) => l.startsWith(`${kind}: bd create `))
	return line.slice(`${kind}: bd create `.length, line.indexOf(' -t '))
}
const shell = (word) => execFileSync('sh', ['-c', `printf '%s' ${word}`], { encoding: 'utf8' })

describe('plan-implement-review record()', () => {
	it.each([
		['command substitution and variables', 'Uses `$props()` and $(touch /tmp/bd-pwned) with $HOME!'],
		['quotes', `it's "quoted"`],
		['line breaks', 'spans\nlines\tand tabs'],
	])('passes a title with %s to bd unchanged', async (_, claim) => {
		const { record, seen } = load({ ok: true, filed: [{ id: 'F1', bdId: 'bd-a' }], followedUp: [{ id: 'F1', bdId: 'bd-b' }] })
		await record(0, { file: [finding(claim)], followUps: [finding(claim)] })
		const oneLine = claim.replace(/\s+/g, ' ')
		expect(shell(titleWord(seen.prompt, 'FILE F1'))).toBe(`Finding F1: ${oneLine}`)
		expect(shell(titleWord(seen.prompt, 'FOLLOW-UP F1'))).toBe(oneLine)
	})

	it('cuts a title at 200 characters', async () => {
		const { record, seen } = load({ ok: true, filed: [], followedUp: [{ id: 'F1', bdId: 'bd-b' }] })
		await record(0, { followUps: [finding('x'.repeat(250))] })
		expect(shell(titleWord(seen.prompt, 'FOLLOW-UP F1'))).toHaveLength(200)
	})

	it('labels each follow-up with a key that a rerun finds, and records the filed ids', async () => {
		const { record, seen } = load({ ok: true, filed: [], followedUp: [{ id: 'F1', bdId: 'bd-a' }] })
		const a = finding('A claim')
		await record(0, { followUps: [a] })
		const label = /-l (followup:bd-x\.1\.review\/[0-9a-f]{8}) /.exec(seen.prompt)?.[1]
		expect(label).toBeTruthy()
		expect(seen.prompt).toContain('before each FOLLOW-UP, with `bd list --all -l <its followup: label> --json`')
		expect(a.bdId).toBe('bd-a')
		// The key follows the finding's file and claim, not its id, which restarts at F1 every run.
		const again = load({ ok: true, filed: [], followedUp: [{ id: 'F9', bdId: 'bd-a' }] })
		await again.record(0, { followUps: [finding('A claim', 'F9')] })
		expect(again.seen.prompt).toContain(`-l ${label} `)
	})

	it('logs a follow-up the agent did not confirm instead of stopping the run', async () => {
		const { record, seen } = load({ ok: true, filed: [] })
		await expect(record(0, { followUps: [finding('A claim')] })).resolves.toBeUndefined()
		expect(seen.logs).toEqual(['Round 0: follow-ups not confirmed filed on bd-x.1.review: F1'])
		await expect(load({ ok: false, error: 'bd down' }).record(0, { followUps: [finding('A claim')] })).rejects.toThrow('Could not record review round 0')
	})
})

describe('plan-implement-review record() escalation', () => {
	const SENTENCE =
		'The single-quoted title after each `bd create` is final: pass it character for character, never rebuilt or reworded from the Text or the finding (bd rejects titles over 500 characters). '
	const FILED = { ok: true, filed: [{ id: 'F1', bdId: 'bd-a' }], followedUp: [] }
	const round = () => {
		const f1 = finding('A claim')
		return { f1, args: { file: [f1], close: [{ bdId: 'bd-c' }] } }
	}

	it.each([
		['fails', { ok: false, error: 'x' }],
		['files fewer issues than it was given', { ok: true, filed: [] }],
		['leaves out ok', { filed: [{ id: 'F1', bdId: 'bd-a' }] }],
	])('escalates once to sonnet when the first answer %s, and uses the escalated filing', async (_, first) => {
		const { record, seen, confirmedFixes } = load([first, FILED])
		const { f1, args } = round()
		await expect(record(0, args)).resolves.toBeUndefined()
		expect(seen.calls.map((c) => c.label)).toEqual(['record:r0', 'record:r0@sonnet'])
		expect(seen.calls[1].prompt).toContain('check their effects first')
		expect(f1.bdId).toBe('bd-a')
		expect(confirmedFixes).toEqual(['bd-c'])
	})

	it('makes one call when the first answer files every FILE', async () => {
		const { record, seen, confirmedFixes } = load([FILED])
		const { f1, args } = round()
		await record(0, args)
		expect(seen.calls.map((c) => c.label)).toEqual(['record:r0'])
		expect(f1.bdId).toBe('bd-a')
		expect(confirmedFixes).toEqual(['bd-c'])
	})

	it('names the last real failure when the escalated answer fails too, and confirms nothing', async () => {
		const both = load([
			{ ok: false, error: 'a' },
			{ ok: false, error: 'b' },
		])
		await expect(both.record(0, round().args)).rejects.toThrow('Could not record review round 0 on bd-x.1.review (b); stopping. Work so far is in /w.')
		expect(both.seen.calls).toHaveLength(2)
		expect(both.confirmedFixes).toEqual([])
		const short = load({ ok: true, filed: [] })
		await expect(short.record(0, round().args)).rejects.toThrow('(filed 0 of 1)')
		expect(short.confirmedFixes).toEqual([])
		await expect(load([null, null]).record(0, round().args)).rejects.toThrow('(record agent failed)')
		// A null escalated answer keeps the first attempt's error.
		await expect(load([{ ok: false, error: 'a' }, null]).record(0, round().args)).rejects.toThrow('(a)')
	})

	it('tells the agent the single-quoted title is final', async () => {
		const { record, seen } = load([FILED])
		await record(0, round().args)
		expect(seen.calls[0].prompt).toContain(`${SENTENCE}Return ok=true`)
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
			'- [F1] a.rs: claim F1 — rejected: why F1',
			'- [F2] a.rs: claim F2 — filed as a follow-up: valid but not blocking; left out of this change',
			'- [F3] a.rs: claim F3 — noted as a nit: valid but not blocking; left out of this change',
		])
	})
})
