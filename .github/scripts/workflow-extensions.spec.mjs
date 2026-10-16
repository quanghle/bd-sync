// The two Copilot workflow extensions (.github/extensions/*/extension.mjs) are scripts: they call joinSession on import and
// keep their logic inside run(ctx). So each is loaded with the SDK import swapped for stubs, then its run is called with
// a fake ctx whose agent answers from a script keyed by label.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'

const SDK_IMPORT = 'import { defineWorkflow, joinSession } from "@github/copilot-sdk/extension";'
const STUB = `const defineWorkflow = (w) => { if (!w.meta?.name || !w.meta.description || !Array.isArray(w.meta.phases) || typeof w.run !== 'function') throw new Error('defineWorkflow needs meta { name, description, phases } and run'); return w; };
const joinSession = async ({ workflows }) => { globalThis.__loaded = workflows[0]; return { workspacePath: globalThis.__workspace }; };`

let tmp
let n = 0
/** The workflow an extension defines, and the session folder it was told. */
async function load(name, workspace) {
	const source = readFileSync(new URL(`../extensions/${name}/extension.mjs`, import.meta.url), 'utf8')
	if (!source.includes(SDK_IMPORT)) throw new Error(`${name} no longer imports the SDK as the spec expects`)
	const file = join(tmp, `${name}-${n++}.mjs`)
	writeFileSync(file, source.replace(SDK_IMPORT, STUB))
	globalThis.__workspace = workspace
	await import(pathToFileURL(file).href)
	return globalThis.__loaded
}

/** A ctx whose agent answers from reply(label, opts, prompt) and records every call. */
function fakeCtx(args, reply, runId = '11111111-2222-4333-8444-555555555555') {
	const calls = []
	const logs = []
	const phases = []
	return {
		calls,
		logs,
		phases,
		runId,
		args,
		agent: async (prompt, opts) => {
			calls.push({ prompt, ...opts })
			return reply(opts.label, opts, prompt)
		},
		log: (m) => logs.push(m),
		phase: (p) => phases.push(p),
		parallel: (thunks) => Promise.all(thunks.map((t) => t())),
		pipeline: (items, ...stages) => Promise.all(items.map(async (item, i) => stages.reduce(async (prev, s) => s(await prev, item, i), undefined))),
	}
}

beforeEach(() => {
	tmp = mkdtempSync(join(tmpdir(), 'workflow-ext-'))
})
afterEach(() => rmSync(tmp, { recursive: true, force: true }))

const CLAIM = { ok: true, token: 'tok', actor: 'me/copilot-1', root: '/r' }
const PLAN = {
	summary: 's',
	requirements: [{ id: 'R1', text: 'x', acceptance: 'a' }],
	steps: [{ id: 'S1', title: 't', covers: ['R1'], files: ['a.md'], approach: 'do it', tests: 'none' }],
	decisions: [],
}
const FOUND = { file: 'src/a.rs', line: 4, severity: 'minor', category: 'correctness', claim: 'Handles nothing', evidence: 'e' }
const ARGS = { requirements: 'x', issue: 'bd-1', plan: PLAN, skipImplement: true, workdir: '/w', baseline: 'abc12345abc', actor: 'me/copilot-1', shadowReview: false }

describe('plan-implement-review', () => {
	/** A scripted run over finished work: claim, setup, a green gate, then the reviewers. */
	const script = (over = {}) => (label, opts) => {
		const base = label.replace(/@escalated$/, '')
		if (over[label] !== undefined) return typeof over[label] === 'function' ? over[label](opts) : over[label]
		if (base === 'claim') return CLAIM
		if (base.startsWith('heartbeat')) return { ok: true }
		if (base === 'setup') return { workdir: '/w', baseline: 'abc12345abc', target: '/t', branch: 'b' }
		if (base.startsWith('gate:')) return { passed: true, failures: [], snapshot: 'snap1', changedFiles: ['README.md'] }
		if (base.startsWith('review:')) return { findings: [] }
		if (base.startsWith('record:')) return { ok: true, filed: [], followedUp: [] }
		if (base.startsWith('validate:')) return { valid: true, blocking: false, reasoning: 'real but minor' }
		return null
	}

	it('runs the mechanical agents as the task agent at low effort', async () => {
		const wf = await load('plan-implement-review', undefined)
		const ctx = fakeCtx(ARGS, script())
		const got = await wf.run(ctx)
		expect(got.status).toBe('done')
		const claim = ctx.calls.find((c) => c.label === 'claim')
		expect(claim).toMatchObject({ agent: 'task', reasoningEffort: 'low' })
		expect(claim.prompt).toContain('bd -C <that path> claim bd-1 --ttl 30m --json --actor "me/copilot-1"')
		expect(ctx.calls.find((c) => c.label === 'review:code:r0')).toMatchObject({ agent: 'code-review' })
	})

	it('escalates a mechanical agent that fails its schema once, to general-purpose at medium, with an @escalated label', async () => {
		const wf = await load('plan-implement-review', undefined)
		let tries = 0
		const ctx = fakeCtx(ARGS, script({ claim: () => (tries++ ? CLAIM : null) }))
		await wf.run(ctx)
		const claims = ctx.calls.filter((c) => c.label.startsWith('claim'))
		expect(claims.map((c) => [c.label, c.agent, c.reasoningEffort])).toEqual([
			['claim', 'task', 'low'],
			['claim@escalated', 'general-purpose', 'medium'],
		])
		expect(claims[1].prompt).toContain('check their effects first')
	})

	it('stops when the escalated claim fails too, never retrying at the same level', async () => {
		const wf = await load('plan-implement-review', undefined)
		const ctx = fakeCtx(ARGS, script({ claim: null, 'claim@escalated': null }))
		const got = await wf.run(ctx)
		expect(got).toMatchObject({ status: 'escalated', reason: expect.stringMatching(/could not claim bd-1/) })
		expect(ctx.calls.filter((c) => c.label.startsWith('claim'))).toHaveLength(2)
	})

	it('throws when the lease is lost: a failed heartbeat whose lease now belongs to someone else', async () => {
		const wf = await load('plan-implement-review', undefined)
		const ctx = fakeCtx(
			ARGS,
			script({
				'heartbeat:0': { ok: false, error: 'held by other' },
				'heartbeat:0@escalated': { ok: false, error: 'held by other' },
				'heartbeat:0:lease': { has: true, holder: 'someone/else', token: 'x' },
			}),
		)
		await expect(wf.run(ctx)).rejects.toThrow(/Lost the lease on bd-1/)
	})

	it('keeps going when a heartbeat fails but the lease is still the actor\'s with the same token', async () => {
		const wf = await load('plan-implement-review', undefined)
		const ctx = fakeCtx(
			ARGS,
			script({
				'heartbeat:0': { ok: false, error: 'mangled' },
				'heartbeat:0@escalated': { ok: false, error: 'mangled' },
				'heartbeat:0:lease': { has: true, holder: 'me/copilot-1', token: 'tok' },
			}),
		)
		expect((await wf.run(ctx)).status).toBe('done')
	})

	it('validates its arguments', async () => {
		const wf = await load('plan-implement-review', undefined)
		await expect(wf.run(fakeCtx({}, script()))).rejects.toThrow(/args.requirements is required/)
		await expect(wf.run(fakeCtx({ requirements: 'x', tier: 'huge' }, script()))).rejects.toThrow(/args.tier must be/)
		await expect(wf.run(fakeCtx({ requirements: 'x', skipImplement: true }, script()))).rejects.toThrow(/skipImplement needs/)
	})

	describe('shadow reviewers and the recorded agents', () => {
		const SHADOW = { model: 'gpt-6-astra', effort: 'xhigh' }
		let workspace
		beforeEach(() => {
			workspace = join(tmp, 'session')
			mkdirSync(workspace)
		})
		const recorded = (run) => {
			const dir = join(workspace, 'files', 'workflow-agents')
			return readFileSync(join(dir, `${run}.jsonl`), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
		}

		it('runs each reviewer again at the shadow model and effort, with the same prompt and its findings kept apart', async () => {
			const wf = await load('plan-implement-review', workspace)
			const ctx = fakeCtx(
				{ ...ARGS, shadowReview: SHADOW },
				script({ 'review:code:r0': { findings: [FOUND] }, 'review:code:r0@shadow:gpt-6-astra-xhigh': { findings: [{ ...FOUND, line: 5 }] } }),
			)
			const got = await wf.run(ctx)
			const real = ctx.calls.find((c) => c.label === 'review:code:r0')
			const shadow = ctx.calls.find((c) => c.label === 'review:code:r0@shadow:gpt-6-astra-xhigh')
			expect(shadow).toMatchObject({ model: 'gpt-6-astra', reasoningEffort: 'xhigh', agent: 'code-review' })
			expect(shadow.prompt).toBe(real.prompt)
			expect(real.model).toBeUndefined()
			expect(got.shadowFindings.find((s) => s.kind === 'code')).toMatchObject({ round: 0, model: 'gpt-6-astra', effort: 'xhigh', findings: [{ line: 5 }] })
			// Only the real finding is validated.
			expect(ctx.calls.filter((c) => c.label.startsWith('validate:'))).toHaveLength(1)
		})

		it('runs Sonnet medium and Opus high shadows when shadowReview is left out', async () => {
			const wf = await load('plan-implement-review', workspace)
			const { shadowReview, ...args } = ARGS
			const ctx = fakeCtx(args, script({ 'review:code:r0': { findings: [] } }))
			const got = await wf.run(ctx)
			const shadows = ctx.calls.filter((c) => c.label.startsWith('review:code:r0@shadow:'))
			expect(shadows.map((c) => [c.label, c.model, c.reasoningEffort])).toEqual([
				['review:code:r0@shadow:claude-sonnet-5.5-medium', 'claude-sonnet-5.5', 'medium'],
				['review:code:r0@shadow:claude-opus-5.5-high', 'claude-opus-5.5', 'high'],
			])
			expect(got.shadowFindings.length).toBeGreaterThan(0)
		})

		it('runs no shadows with shadowReview: false', async () => {
			const wf = await load('plan-implement-review', workspace)
			const ctx = fakeCtx(ARGS, script())
			const got = await wf.run(ctx)
			expect(ctx.calls.some((c) => c.label.includes('@shadow:'))).toBe(false)
			expect(got.shadowFindings).toBeUndefined()
		})

		it('records the run, and each review and validate agent with its prompt hash and result, but no prompt', async () => {
			const wf = await load('plan-implement-review', workspace)
			const ctx = fakeCtx(
				{ ...ARGS, reviewStep: 'bd-1.review', shadowReview: SHADOW, tier: 'standard' },
				script({ 'review:code:r0': { findings: [FOUND] }, 'review:code:r0@shadow:gpt-6-astra-xhigh': { findings: [] } }),
			)
			await wf.run(ctx)
			const rows = recorded(ctx.runId)
			expect(rows[0]).toEqual({ run: ctx.runId, type: 'run', workflow: 'plan-implement-review', reviewStep: 'bd-1.review', issue: 'bd-1', tier: 'standard' })
			const labels = rows.filter((r) => r.type === 'agent').map((r) => r.label)
			expect(labels.toSorted()).toEqual(['review:code:r0', 'review:code:r0@shadow:gpt-6-astra-xhigh', 'validate:r0:F1', 'review:requirements:r0', 'review:requirements:r0@shadow:gpt-6-astra-xhigh'].toSorted())
			const real = rows.find((r) => r.label === 'review:code:r0')
			const shadow = rows.find((r) => r.label === 'review:code:r0@shadow:gpt-6-astra-xhigh')
			expect(real).toMatchObject({ kind: 'code-review', model: null, effort: null, result: { findings: [FOUND] } })
			expect(shadow).toMatchObject({ model: 'gpt-6-astra', effort: 'xhigh' })
			expect(real.prompt_sha256).toMatch(/^[0-9a-f]{64}$/)
			expect(real.prompt_sha256).toBe(shadow.prompt_sha256)
			expect(rows.find((r) => r.label === 'validate:r0:F1')).toMatchObject({ finding: { file: 'src/a.rs', line: 4, claim: 'Handles nothing' }, result: { valid: true } })
			expect(JSON.stringify(rows)).not.toContain('You are')
			expect(rows.some((r) => r.label === 'claim' || r.label === 'setup')).toBe(false)
		})

		it('records nothing without a session folder, and never fails the run when it cannot write', async () => {
			const none = await load('plan-implement-review', undefined)
			expect((await none.run(fakeCtx(ARGS, script()))).status).toBe('done')
			// A folder under a regular file cannot be created.
			writeFileSync(join(tmp, 'file'), 'x')
			const blocked = await load('plan-implement-review', join(tmp, 'file'))
			expect((await blocked.run(fakeCtx(ARGS, script()))).status).toBe('done')
		})
	})
})

describe('score-issue', () => {
	const SETUP = { root: '/r', rubric: 2, estimate: 3 }
	const dims = (over = {}) => Object.fromEntries(['correctness', 'scope', 'quality', 'verification', 'process', 'autonomy'].map((d) => [d, { score: 4, evidence: `${d} evidence`, ...over[d] }]))
	const judgement = (over = {}) => ({
		dims: dims(over.dims),
		overall: 4,
		complexity: { score: 4, evidence: 'big' },
		confidence: 'high',
		summary: 'went fine',
		strengths: ['tests'],
		problems: [{ dimension: 'scope', problem: 'extra', evidence: 'a.rs:1' }],
		change: 'abc..def',
		...over.top,
	})
	const script = (over = {}) => (label) => {
		if (over[label] !== undefined) return over[label]
		if (label === 'setup') return SETUP
		if (label === 'judge') return judgement()
		if (label === 'trace') return { ok: true, summary: 'Work: 3 agents, 1.2 credits' }
		if (label === 'record') return { ok: true }
		return null
	}

	it('judges with gpt-6-astra at xhigh, the rest on the task agent, and records the draft as the judge model', async () => {
		const wf = await load('score-issue', undefined)
		const ctx = fakeCtx({ issue: 'bd-1', actor: 'me/copilot-1', range: 'main..x' }, script())
		const got = await wf.run(ctx)
		expect(ctx.calls.map((c) => [c.label, c.agent, c.model, c.reasoningEffort])).toEqual([
			['setup', 'task', undefined, 'low'],
			['judge', 'general-purpose', 'gpt-6-astra', 'xhigh'],
			['trace', 'task', undefined, 'low'],
			['record', 'task', undefined, 'low'],
		])
		expect(ctx.phases).toEqual(['Setup', 'Judge', 'Trace', 'Record'])
		expect(got).toMatchObject({ status: 'scored', recorded: true, score: { rubric: 2, overall: 4, complexity: 4, confidence: 'high', by: 'gpt-6-astra' } })
		const judge = ctx.calls[1].prompt
		expect(judge).toContain('git -C /r log --stat main..x')
		expect(judge).toContain("del(.metadata.complexity_estimate, .metadata.work, .metadata.score, .metadata.score_judge)")
		// The judge is never shown the estimate or the trace.
		expect(judge).not.toContain('trace-run.mjs')
		const trace = ctx.calls[2].prompt
		expect(trace).toContain('node /r/.github/scripts/trace-run.mjs bd-1 --root /r --summary --write --actor "me/copilot-1"')
		const record = ctx.calls[3].prompt
		expect(record).toContain(`bd -C /r update bd-1 --set-metadata 'score_judge={"rubric":2,"overall":4,`)
		expect(record).toContain('"by":"gpt-6-astra"')
		expect(record).toContain('Judge\'s score (rubric v2, gpt-6-astra): overall 4/5, confidence high')
		expect(record).toContain('Complexity: 4/5 (estimated 3, gap +1). big')
		expect(record).toContain('Work: 3 agents, 1.2 credits')
		expect(record).toContain('--actor "me/copilot-1"')
	})

	it('applies the rubric caps: overall at most correctness, and 2 when any dimension is 1', async () => {
		const wf = await load('score-issue', undefined)
		const capped = await wf.run(fakeCtx({ issue: 'bd-1', dryRun: true }, script({ judge: judgement({ dims: { correctness: { score: 3 } }, top: { overall: 5 } }) })))
		expect(capped.score.overall).toBe(3)
		expect(capped.caps).toEqual(['at most correctness (3)'])
		const one = await wf.run(fakeCtx({ issue: 'bd-1', dryRun: true }, script({ judge: judgement({ dims: { process: { score: 1 } }, top: { overall: 4 } }) })))
		expect(one.score.overall).toBe(2)
		expect(one.caps).toEqual(['a dimension at 1 caps it at 2'])
		const nulled = await wf.run(fakeCtx({ issue: 'bd-1', dryRun: true }, script({ judge: judgement({ dims: { correctness: { score: null } }, top: { overall: 4 } }) })))
		expect(nulled.score).toMatchObject({ overall: 4, dims: { correctness: null } })
	})

	it('writes nothing on a dry run, and traces without --write', async () => {
		const wf = await load('score-issue', undefined)
		const ctx = fakeCtx({ issue: 'bd-1', dryRun: true }, script())
		const got = await wf.run(ctx)
		expect(got).toMatchObject({ status: 'scored', recorded: false })
		expect(ctx.calls.map((c) => c.label)).toEqual(['setup', 'judge', 'trace'])
		expect(ctx.calls[2].prompt).toContain('--summary\n')
		expect(ctx.calls[2].prompt).not.toContain('--write')
	})

	it('reports an unusable judgement, a missing rubric and a failed trace', async () => {
		const wf = await load('score-issue', undefined)
		expect(await wf.run(fakeCtx({ issue: 'bd-1' }, script({ setup: { root: '/r', error: 'missing' } })))).toMatchObject({ status: 'failed', reason: expect.stringMatching(/no usable rubric/) })
		expect(await wf.run(fakeCtx({ issue: 'bd-1' }, script({ judge: null })))).toMatchObject({ status: 'failed', reason: 'the judge failed' })
		expect(await wf.run(fakeCtx({ issue: 'bd-1' }, script({ judge: judgement({ dims: { scope: { score: 9 } } }) })))).toMatchObject({ status: 'failed', reason: expect.stringMatching(/unusable score \(scope\)/) })
		const traceFailed = await wf.run(fakeCtx({ issue: 'bd-1', dryRun: true }, script({ trace: null })))
		expect(traceFailed.work).toBe('Work trace failed: trace agent failed')
		const notRecorded = await wf.run(fakeCtx({ issue: 'bd-1' }, script({ record: { ok: false, error: 'exit 7' } })))
		expect(notRecorded).toMatchObject({ status: 'scored', recorded: false, reason: 'could not record: exit 7' })
	})

	it('needs an issue, and takes a bare string as one', async () => {
		const wf = await load('score-issue', undefined)
		await expect(wf.run(fakeCtx({}, script()))).rejects.toThrow(/args.issue is required/)
		const ctx = fakeCtx('bd-9', script())
		await wf.run(ctx)
		expect(ctx.calls[0].prompt).toContain('bd -C <root> show bd-9 --json')
	})
})
