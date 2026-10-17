// .claude/workflows/score-issue.js end to end with a scripted agent: the rubric's caps on overall, the two bd writes the
// record agent is handed (as the caller's actor when given one), and ops()' single escalation of a mechanical agent. A
// workflow script isn't a module (top-level await and return), so this runs its body as an async function with the
// workflow globals (args, agent, log, phase) stubbed.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from './expect.mjs'

const source = readFileSync(fileURLToPath(new URL('../../.claude/workflows/score-issue.js', import.meta.url)), 'utf8').replace(
	/^export const meta = /m,
	'const meta = ',
)
const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor

const dim = (score) => ({ score, evidence: 'e' })
const judgeReply = (dims, overall) => ({
	dims: Object.fromEntries(Object.entries(dims).map(([d, s]) => [d, dim(s)])),
	overall,
	complexity: dim(3),
	confidence: 'high',
	summary: 's',
	change: 'main..x',
})
const DIMS5 = { correctness: 5, scope: 5, quality: 5, verification: 5, process: 5, autonomy: 5 }

/** Runs the workflow; replies maps an agent label to its answer (a function of the call count, or a value). */
async function run(args, replies) {
	const calls = []
	const agent = async (prompt, opts) => {
		calls.push({ prompt, ...opts })
		const r = replies[opts.label]
		return typeof r === 'function' ? r(calls.filter((c) => c.label === opts.label).length) : r
	}
	const result = await new AsyncFunction('args', 'agent', 'log', 'phase', source)(args, agent, () => {}, () => {})
	return { result, calls }
}

const base = {
	setup: { root: '/r', rubric: 3, estimate: 2 },
	trace: { ok: true, summary: 'trace' },
	record: { ok: true },
}

describe('score-issue.js', () => {
	it('caps overall at correctness and at 2 when a dimension is 1', async () => {
		const a = await run({ issue: 'bd-1', dryRun: true }, { ...base, judge: judgeReply({ ...DIMS5, correctness: 3 }, 5) })
		expect(a.result.score.overall).toBe(3)
		const b = await run({ issue: 'bd-1', dryRun: true }, { ...base, judge: judgeReply({ ...DIMS5, process: 1 }, 4) })
		expect(b.result.score.overall).toBe(2)
		expect(b.result.score).toMatchObject({ rubric: 3, complexity: 3, by: 'fable' })
	})

	it("writes the draft and the comment as the caller's actor when given one", async () => {
		const { result, calls } = await run({ issue: 'bd-1', actor: 'Quang Le/claude-x' }, { ...base, judge: judgeReply(DIMS5, 5) })
		expect(result).toMatchObject({ status: 'scored', recorded: true })
		const rec = calls.find((c) => c.label === 'record')
		expect(rec.prompt).toContain(`bd -C /r update bd-1 --set-metadata 'score_judge={"rubric":3,"overall":5,`)
		expect(rec.prompt).toContain(`--actor "Quang Le/claude-x"`)
		expect(rec.prompt).toContain('bd -C /r comment add bd-1 <Text> --actor "Quang Le/claude-x"')
		expect(rec.prompt).not.toContain('--session flag')
		expect(calls.find((c) => c.label === 'trace').prompt).toContain('--write --actor "Quang Le/claude-x"')
	})

	it("without an actor, asks the record agent for its hook's --session", async () => {
		const { calls } = await run({ issue: 'bd-1' }, { ...base, judge: judgeReply(DIMS5, 5) })
		const rec = calls.find((c) => c.label === 'record')
		expect(rec.prompt).toContain('--session flag')
		expect(rec.prompt).not.toContain('--actor')
	})

	it('runs mechanical agents on haiku and escalates one failed schema once to sonnet', async () => {
		const { result, calls } = await run(
			{ issue: 'bd-1', dryRun: true },
			{ ...base, setup: (n) => (n === 1 ? null : base.setup), 'setup@sonnet': base.setup, judge: judgeReply(DIMS5, 5) },
		)
		expect(result.status).toBe('scored')
		const setups = calls.filter((c) => c.label.startsWith('setup'))
		expect(setups.map((c) => [c.label, c.model, c.effort])).toEqual([
			['setup', 'haiku', 'low'],
			['setup@sonnet', 'sonnet', 'medium'],
		])
		expect(calls.find((c) => c.label === 'judge')).toMatchObject({ model: 'fable', effort: 'high' })
	})

	it('fails without a usable rubric after the escalation', async () => {
		const { result, calls } = await run({ issue: 'bd-1' }, { ...base, setup: null, 'setup@sonnet': null })
		expect(result.status).toBe('failed')
		expect(calls.filter((c) => c.label.startsWith('setup')).length).toBe(2)
	})
})
