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
		if (base === 'setup') return { workdir: '/w', baseline: 'abc12345abc', target: '/w/target', branch: 'b' }
		if (base.startsWith('gate:')) return { passed: true, failures: [], snapshot: 'snap1', changedFiles: ['README.md'], log: '/x/gate.log', marker: 'bd-gate: dir=/w run=bd-1' }
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

	it.each(['huge', 'High', 7])('rejects reviewEffort %j at start, before any agent runs', async (v) => {
		const wf = await load('plan-implement-review', undefined)
		const ctx = fakeCtx({ requirements: 'x', reviewEffort: v }, script())
		await expect(wf.run(ctx)).rejects.toThrow(/args\.reviewEffort must be one of low\|medium\|high\|xhigh\|max/)
		expect(ctx.calls).toHaveLength(0)
	})

	it('lists reviewEffort in its args schema with the five efforts', async () => {
		const wf = await load('plan-implement-review', undefined)
		expect(wf.meta.argsSchema.properties.reviewEffort.enum).toEqual(['low', 'medium', 'high', 'xhigh', 'max'])
	})

	describe('logs, the suite lock and the gate marker', () => {
		const run = async (args, over = {}) => {
			const wf = await load('plan-implement-review', undefined)
			const ctx = fakeCtx(args, script(over))
			return { ctx, got: await wf.run(ctx) }
		}
		const promptOf = (ctx, label) => ctx.calls.find((c) => c.label === label).prompt
		const GREEN = { passed: true, failures: [], snapshot: 'snap1', changedFiles: ['README.md'], log: '/x/gate.log', marker: 'bd-gate: dir=/w run=bd-1' }
		const FOREIGN = { ...GREEN, marker: 'bd-gate: dir=/w/other run=bd-1' }
		const UNMARKED = { passed: true, failures: [], snapshot: 'snap1', changedFiles: ['README.md'] }
		const LINT = { passed: false, failures: [{ command: 'cargo clippy', excerpt: 'warning: x' }], snapshot: 'snap1', changedFiles: ['README.md'], log: '/x/gate.log', marker: 'bd-gate: dir=/w run=bd-1' }

		it('rejects a logDir that is not an absolute directory without .. or control characters, at start', async () => {
			const wf = await load('plan-implement-review', undefined)
			for (const logDir of ['rel', '/a/../b', '/a\nb']) {
				const ctx = fakeCtx({ ...ARGS, logDir }, script())
				await expect(wf.run(ctx), JSON.stringify(logDir)).rejects.toThrow(/args\.logDir must be/)
				expect(ctx.calls, JSON.stringify(logDir)).toHaveLength(0)
			}
		})

		it('names each gate attempt\'s own log under logDir, or under the os tmpdir without it', async () => {
			const { ctx } = await run({ ...ARGS, logDir: '/logs/' })
			const gate = promptOf(ctx, 'gate:impl')
			expect(gate).toContain(`> '/logs/bd-1/gate-impl.log' 2>&1`)
			expect(gate).toContain(`mkdir -p '/logs/bd-1'`)
			expect(gate).toContain('bd-gate: dir=$PWD run=bd-1')
			expect(gate).toContain(`head -1 '/logs/bd-1/gate-impl.log'`)
			expect(ctx.logs).toContain('Logs in /logs/bd-1')

			const { ctx: dflt } = await run(ARGS)
			expect(promptOf(dflt, 'gate:impl')).toContain(`${join(tmpdir(), 'plan-implement-review')}/bd-1/gate-impl.log`)
		})

		it('runs the full suite under the suite lock, and reruns it while the lock is busy', async () => {
			const { ctx } = await run(ARGS)
			const gate = promptOf(ctx, 'gate:impl')
			expect(gate).toContain('if [ -f .github/scripts/suite-lock.mjs ]; then node .github/scripts/suite-lock.mjs --run bd-1 -- cargo test --workspace --locked; else cargo test --workspace --locked; fi')
			expect(gate).toContain('exit[test]=75')
			expect(gate).toContain(`grep '^exit\\[' `)
			expect(gate).toContain('600000')
			expect(gate).not.toContain('tee ')
		})

		it('gives validators and gate-fix coders their own files', async () => {
			const { ctx } = await run({ ...ARGS, logDir: '/logs' }, { 'review:code:r0': { findings: [FOUND] }, 'gate:impl': LINT })
			const validate = promptOf(ctx, 'validate:r0:F1')
			expect(validate).toContain(`'/logs/bd-1/validate-r0-F1.log'`)
			expect(validate).toContain('exit 75')
			const fix = promptOf(ctx, 'coder:gate-fix:impl:1')
			expect(fix).toContain(`> '/logs/bd-1/coder-gate-fix-impl-1.log' 2>&1; echo "exit=$?"`)
			expect(fix).not.toContain('validate-r0-F1.log')
			expect(promptOf(ctx, 'gate:impl:1')).toContain(`'/logs/bd-1/gate-impl-1.log'`)
		})

		it('gives real and shadow reviewers the same prompt, with a mktemp log and no label or model', async () => {
			const wf = await load('plan-implement-review', undefined)
			const ctx = fakeCtx({ ...ARGS, logDir: '/logs', shadowReview: { model: 'gpt-6-astra', effort: 'xhigh' } }, script())
			await wf.run(ctx)
			const real = promptOf(ctx, 'review:code:r0')
			expect(promptOf(ctx, 'review:code:r0@shadow:gpt-6-astra-xhigh')).toBe(real)
			expect(real).toContain(`mktemp '/logs/bd-1/review-code-r0.XXXXXX'`)
			expect(real).not.toContain('@shadow')
			expect(real).not.toContain('gpt-6-astra')
			expect(promptOf(ctx, 'review:requirements:r0')).toContain(`mktemp '/logs/bd-1/review-requirements-r0.XXXXXX'`)
		})

		it.each([
			['names another directory', FOREIGN, 'its marker says "bd-gate: dir=/w/other run=bd-1"'],
			['passes without a marker', UNMARKED, 'no bd-gate marker although the gate passed'],
		])('escalates a gate whose log %s on both attempts, without a gate fix', async (_, report, says) => {
			const { ctx, got } = await run(ARGS, { 'gate:impl': report, 'gate:impl@escalated': report })
			expect(got.status).toBe('escalated')
			expect(got.reason).toMatch(/^gate log contaminated/)
			expect(got.reason).toContain(says)
			expect(got.reason).toContain('expected dir=/w run=bd-1')
			expect(got.reason).toContain(`(log ${join(tmpdir(), 'plan-implement-review')}/bd-1/gate-impl-escalated.log)`)
			expect(ctx.calls.filter((c) => c.label.startsWith('gate:')).map((c) => [c.label, c.agent])).toEqual([
				['gate:impl', 'task'],
				['gate:impl@escalated', 'general-purpose'],
			])
			expect(ctx.calls.some((c) => c.label.startsWith('coder:gate-fix'))).toBe(false)
			expect(ctx.calls.some((c) => c.label.startsWith('review:'))).toBe(false)
			expect(ctx.logs.some((l) => l.startsWith('gate gate:impl: log contaminated'))).toBe(true)
		})

		it('takes a clean escalated attempt after a contaminated one', async () => {
			const { ctx, got } = await run(ARGS, { 'gate:impl': FOREIGN, 'gate:impl@escalated': GREEN })
			expect(got.status).toBe('done')
			expect(promptOf(ctx, 'gate:impl@escalated')).toContain('/bd-1/gate-impl-escalated.log')
		})

		it('escalates a contaminated gate after review fixes, keeping the open findings', async () => {
			const { ctx, got } = await run(ARGS, {
				'review:code:r0': { findings: [FOUND] },
				'validate:r0:F1': { valid: true, blocking: true, reasoning: 'real', fixInstruction: 'fix it' },
				'planner:triage:r0': { items: [{ id: 'F1', action: 'fix', reason: 'r', instruction: 'i' }], converging: true },
				'coder:fix:r1': { summary: 's', filesChanged: ['src/a.rs'], changes: [{ id: 'F1', change: 'c' }] },
				'gate:r1': FOREIGN,
				'gate:r1@escalated': FOREIGN,
			})
			expect(got.status).toBe('escalated')
			expect(got.reason).toMatch(/^gate log contaminated/)
			expect(got.open.map((f) => f.id)).toEqual(['F1'])
			expect(promptOf(ctx, 'coder:fix:r1')).toContain('/bd-1/coder-fix-r1.log')
			expect(ctx.calls.some((c) => c.label.startsWith('coder:gate-fix'))).toBe(false)
		})

		it('gives each implement coder its own file', async () => {
			const args = { ...ARGS, skipImplement: undefined }
			const { ctx, got } = await run({ ...args, logDir: '/logs' }, {
				'planner:critic:0': { approved: true, issues: [] },
				'coder:S1': { summary: 'done', filesChanged: ['a.md'] },
			})
			expect(got.status).toBe('done')
			expect(promptOf(ctx, 'coder:S1')).toContain(`'/logs/bd-1/coder-S1.log'`)
		})

		it('asks every setup branch for the worktree\'s own target dir, never a shared one', async () => {
			const LIT = 'echo "$(git rev-parse --show-toplevel)/target"'
			const { ctx } = await run(ARGS)
			expect(promptOf(ctx, 'setup')).toContain('^{tree}')
			expect(promptOf(ctx, 'setup')).toContain(LIT)
			expect(promptOf(ctx, 'setup')).not.toContain('implement-review')

			// skipImplement needs a baseline and a baseline needs a workdir, so the other two branches plan only.
			const rest = { ...ARGS, skipImplement: undefined, baseline: undefined }
			const critic = { 'planner:critic:0': { approved: true, issues: [] } }
			for (const [args, branch] of [
				[{ ...rest, planOnly: true }, 'run this snapshot command'],
				[{ ...rest, workdir: undefined, planOnly: true }, 'git worktree add'],
			]) {
				const { ctx, got } = await run(args, critic)
				const what = JSON.stringify({ workdir: args.workdir })
				expect(got.status, what).toBe('planned')
				expect(promptOf(ctx, 'setup'), what).toContain(branch)
				expect(promptOf(ctx, 'setup'), what).toContain(LIT)
				expect(promptOf(ctx, 'setup'), what).not.toContain('implement-review')
			}
		})
	})

	describe('setup target', () => {
		const run = async (args, over = {}) => {
			const wf = await load('plan-implement-review', undefined)
			const ctx = fakeCtx(args, script(over))
			return { ctx, got: await wf.run(ctx) }
		}
		const promptOf = (ctx, label) => ctx.calls.find((c) => c.label === label).prompt
		const targetLines = (ctx) => ctx.logs.filter((l) => /^setup setup(@escalated)?: target /.test(l))
		const critic = { 'planner:critic:0': { approved: true, issues: [] } }

		// [name, args.workdir, the setup report, accepted]: the same table as plan-implement-review.logs.spec.mjs's
		// SETUP_CASES, so both harnesses give the same verdicts.
		const SETUP_CASES = [
			['its own target', '/w', { workdir: '/w', target: '/w/target' }, true],
			['a trailing slash', '/w', { workdir: '/w', target: '/w/target/' }, true],
			['a doubled slash', '/w', { workdir: '/w', target: '/w//target' }, true],
			['a Windows path', 'C:\\w', { workdir: 'C:\\w', target: 'C:/w/target' }, true],
			['a target outside the workdir', '/w', { workdir: '/w', target: '/t' }, false],
			["another checkout's target", '/w', { workdir: '/w', target: '/r/target' }, false],
			['a subdirectory\'s target', '/w', { workdir: '/w', target: '/w/sub/target' }, false],
			['another workdir than args.workdir', '/w', { workdir: '/r', target: '/r/target' }, false],
			['args.workdir with a trailing slash', '/w/', { workdir: '/w', target: '/w/target' }, true],
			['no args.workdir', undefined, { workdir: '/x', target: '/x/target' }, true],
		]

		// planOnly: setup and the critic run, and no gate marker (dir=/w) can escalate a case for another reason. A baseline
		// needs a workdir, so the no-workdir case (the worktree-add branch) drops it.
		it.each(SETUP_CASES)('%s', async (_, workdir, report, ok) => {
			const reply = { ...report, baseline: 'abc12345abc', branch: 'b' }
			const args = { ...ARGS, workdir, baseline: workdir ? ARGS.baseline : undefined, skipImplement: undefined, planOnly: true }
			const { ctx, got } = await run(args, { ...critic, setup: reply, 'setup@escalated': reply })
			if (ok) {
				expect(got.status).toBe('planned')
				expect(targetLines(ctx)).toEqual([])
			} else {
				expect(got.status).toBe('escalated')
				expect(got.reason).toMatch(/^setup agent failed/)
				expect(ctx.calls.some((c) => c.label.startsWith('planner:'))).toBe(false)
				const lines = targetLines(ctx)
				expect(lines).toHaveLength(2)
				for (const l of lines) {
					expect(l).toContain(report.target)
					expect(l).toContain(`${workdir.replace(/\/+$/, '')}/target`)
				}
			}
		})

		const BAD = { workdir: '/w', baseline: 'abc12345abc', target: '/r/target', branch: 'b' }

		it('escalates a report of another target once, then ends the run before planning', async () => {
			const { ctx, got } = await run(ARGS, { setup: BAD, 'setup@escalated': BAD })
			expect(got.status).toBe('escalated')
			expect(got.reason).toMatch(/^setup agent failed/)
			const setups = ctx.calls.filter((c) => c.label.startsWith('setup'))
			expect(setups.map((c) => [c.label, c.agent])).toEqual([
				['setup', 'task'],
				['setup@escalated', 'general-purpose'],
			])
			expect(ctx.calls.some((c) => /^(planner|coder|gate):/.test(c.label))).toBe(false)
			const lines = targetLines(ctx)
			expect(lines).toHaveLength(2)
			for (const l of lines) {
				expect(l).toContain('/r/target')
				expect(l).toContain('/w/target')
			}
		})

		it('goes on with the escalated report when it names the worktree\'s own target', async () => {
			const { ctx, got } = await run({ ...ARGS, skipImplement: undefined }, {
				...critic,
				setup: BAD,
				'coder:S1': { summary: 'done', filesChanged: ['a.md'] },
			})
			expect(got.status).toBe('done')
			expect(targetLines(ctx)).toHaveLength(1)
			expect(promptOf(ctx, 'coder:S1')).toContain('CARGO_TARGET_DIR=/w/target set')
			expect(promptOf(ctx, 'gate:impl')).toContain("export CARGO_TARGET_DIR='/w/target'")
		})
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
			const args = { ...ARGS, shadowReview: undefined }
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
			// Without reviewEffort a real reviewer gets no effort key at all: the session's.
			const realCalls = ctx.calls.filter((c) => /^review:[^@]+:r0$/.test(c.label))
			expect(realCalls.length).toBeGreaterThan(0)
			for (const c of realCalls) expect('reasoningEffort' in c).toBe(false)
			expect(ctx.logs.some((m) => m.startsWith('Reviewers at effort'))).toBe(false)
			expect(shadow).toMatchObject({ model: 'gpt-6-astra', effort: 'xhigh' })
			expect(real.prompt_sha256).toMatch(/^[0-9a-f]{64}$/)
			expect(real.prompt_sha256).toBe(shadow.prompt_sha256)
			expect(rows.find((r) => r.label === 'validate:r0:F1')).toMatchObject({ finding: { file: 'src/a.rs', line: 4, claim: 'Handles nothing' }, result: { valid: true } })
			expect(JSON.stringify(rows)).not.toContain('You are')
			expect(rows.some((r) => r.label === 'claim' || r.label === 'setup')).toBe(false)
		})

		it('runs the real reviewers at reviewEffort, and nothing else', async () => {
			const wf = await load('plan-implement-review', workspace)
			const ctx = fakeCtx({ ...ARGS, reviewEffort: 'max', shadowReview: SHADOW, tier: 'critical' }, script({ 'review:code:r0': { findings: [FOUND] } }))
			expect((await wf.run(ctx)).status).toBe('done')
			const real = ctx.calls.filter((c) => /^review:[^@]+:r0$/.test(c.label))
			expect(real.map((c) => c.label).toSorted()).toEqual(['review:code:r0', 'review:requirements:r0', 'review:security:r0'])
			for (const c of real) {
				expect(c).toMatchObject({ reasoningEffort: 'max', agent: 'code-review' })
				expect(c.model).toBeUndefined()
				const shadow = ctx.calls.find((s) => s.label === `${c.label}@shadow:gpt-6-astra-xhigh`)
				expect(shadow).toMatchObject({ model: 'gpt-6-astra', reasoningEffort: 'xhigh', agent: 'code-review' })
				expect(shadow.prompt).toBe(c.prompt)
			}
			const validators = ctx.calls.filter((c) => c.label.startsWith('validate:'))
			expect(validators).toHaveLength(1)
			for (const c of validators) expect(c.reasoningEffort).toBe('high')
			for (const label of ['claim', 'setup']) expect(ctx.calls.find((c) => c.label === label)).toMatchObject({ agent: 'task', reasoningEffort: 'low' })
			const gates = ctx.calls.filter((c) => c.label.startsWith('gate:'))
			expect(gates.length).toBeGreaterThan(0)
			for (const c of gates) expect(c).toMatchObject({ agent: 'task', reasoningEffort: 'low' })
			const rows = recorded(ctx.runId).filter((r) => r.type === 'agent')
			for (const kind of ['code', 'requirements', 'security']) {
				const r = rows.find((x) => x.label === `review:${kind}:r0`)
				const sh = rows.find((x) => x.label === `review:${kind}:r0@shadow:gpt-6-astra-xhigh`)
				expect(r).toMatchObject({ model: null, effort: 'max' })
				expect(sh).toMatchObject({ model: 'gpt-6-astra', effort: 'xhigh' })
				expect(r.prompt_sha256).toBe(sh.prompt_sha256)
			}
			expect(ctx.logs).toContain('Reviewers at effort max')
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

	describe('record', () => {
		const SENTENCE =
			'The single-quoted title after each `bd create` is final: pass it character for character, never rebuilt or reworded from the Text or the finding (bd rejects titles over 500 characters). '
		// A blocking finding whose triage fails (planner:triage:r0 answers null): the run files it on the step, then escalates.
		const filing = (over) => script({ 'review:code:r0': { findings: [FOUND] }, 'validate:r0:F1': { valid: true, blocking: true, reasoning: 'real' }, ...over })
		const run = async (over) => {
			const wf = await load('plan-implement-review', undefined)
			const ctx = fakeCtx({ ...ARGS, reviewStep: 'bd-1.review' }, filing(over))
			return { ctx, got: wf.run(ctx) }
		}
		const records = (ctx) => ctx.calls.filter((c) => c.label.startsWith('record:'))

		it.each([
			['fails', { ok: false, error: 'x' }],
			['files fewer issues than it was given', { ok: true, filed: [] }],
		])('escalates once when the record agent %s, and uses the escalated filing', async (_, first) => {
			const { ctx, got } = await run({ 'record:r0': first, 'record:r0@escalated': { ok: true, filed: [{ id: 'F1', bdId: 'bd-9' }], followedUp: [] } })
			const out = await got
			expect(out.status).toBe('escalated')
			expect(out.open[0].bdId).toBe('bd-9')
			expect(records(ctx).map((c) => [c.label, c.agent, c.reasoningEffort])).toEqual([
				['record:r0', 'task', 'low'],
				['record:r0@escalated', 'general-purpose', 'medium'],
			])
		})

		it.each([
			['fails twice', { ok: false, error: 'bd down' }, /Could not record review round 0 on bd-1\.review \(bd down\)/],
			['files short twice', { ok: true, filed: [] }, /\(filed 0 of 1\)/],
			['answers nothing twice', null, /\(record agent failed\)/],
		])('stops with the last real failure when the record agent %s', async (_, answer, error) => {
			const { ctx, got } = await run({ 'record:r0': answer, 'record:r0@escalated': answer })
			await expect(got).rejects.toThrow(error)
			expect(records(ctx)).toHaveLength(2)
		})

		it('tells the agent the single-quoted title is final', async () => {
			const { ctx, got } = await run({ 'record:r0': { ok: true, filed: [{ id: 'F1', bdId: 'bd-9' }], followedUp: [] } })
			expect((await got).status).toBe('escalated')
			expect(ctx.calls.find((c) => c.label === 'record:r0').prompt).toContain(`${SENTENCE}Return ok=true`)
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

	it('escalates a mechanical agent that fails its schema once, to general-purpose at medium, with an @escalated label', async () => {
		const wf = await load('score-issue', undefined)
		const ctx = fakeCtx({ issue: 'bd-1', dryRun: true }, script({ setup: null, 'setup@escalated': SETUP }))
		const got = await wf.run(ctx)
		expect(got.status).toBe('scored')
		const setups = ctx.calls.filter((c) => c.label.startsWith('setup'))
		expect(setups.map((c) => [c.label, c.agent, c.model, c.reasoningEffort])).toEqual([
			['setup', 'task', undefined, 'low'],
			['setup@escalated', 'general-purpose', undefined, 'medium'],
		])
		expect(setups[1].prompt).toContain(setups[0].prompt)
		expect(setups[1].prompt).toContain('check their effects first')
		expect(ctx.logs.some((l) => l.includes('setup failed its schema'))).toBe(true)
	})

	it('fails when the escalated setup fails too, never retrying at the same level', async () => {
		const wf = await load('score-issue', undefined)
		const ctx = fakeCtx({ issue: 'bd-1' }, script({ setup: null }))
		const got = await wf.run(ctx)
		expect(got).toMatchObject({ status: 'failed', reason: 'could not find the main checkout' })
		expect(ctx.calls.map((c) => c.label)).toEqual(['setup', 'setup@escalated'])
	})

	const callsOf = (ctx, prefix) => ctx.calls.filter((c) => c.label.startsWith(prefix))
	const shape = (calls) => calls.map((c) => [c.label, c.agent, c.model, c.reasoningEffort])

	it('escalates a failed trace once, to general-purpose at medium, and keeps the escalated summary as work', async () => {
		const wf = await load('score-issue', undefined)
		for (const bad of [null, { summary: 'x' }]) {
			const note = JSON.stringify(bad)
			const ctx = fakeCtx({ issue: 'bd-1', dryRun: true }, script({ trace: bad, 'trace@escalated': { ok: true, summary: 'Work: escalated' } }))
			const got = await wf.run(ctx)
			const traces = callsOf(ctx, 'trace')
			expect(shape(traces), note).toEqual([
				['trace', 'task', undefined, 'low'],
				['trace@escalated', 'general-purpose', undefined, 'medium'],
			])
			expect(traces[1].prompt, note).toContain(traces[0].prompt)
			expect(traces[1].prompt, note).toContain('check their effects first')
			expect(got.work, note).toBe('Work: escalated')
		}
	})

	it('gives up on the trace after one escalation', async () => {
		const wf = await load('score-issue', undefined)
		const ctx = fakeCtx({ issue: 'bd-1', dryRun: true }, script({ trace: null, 'trace@escalated': { summary: 'x' } }))
		const got = await wf.run(ctx)
		expect(callsOf(ctx, 'trace').map((c) => c.label)).toEqual(['trace', 'trace@escalated'])
		expect(got.work).toBe('Work trace failed: trace agent failed')
	})

	it('escalates a failed record once and records with the escalated answer', async () => {
		const wf = await load('score-issue', undefined)
		const ctx = fakeCtx({ issue: 'bd-1' }, script({ record: null, 'record@escalated': { ok: true } }))
		const got = await wf.run(ctx)
		expect(got).toMatchObject({ status: 'scored', recorded: true })
		const recs = callsOf(ctx, 'record')
		expect(shape(recs)).toEqual([
			['record', 'task', undefined, 'low'],
			['record@escalated', 'general-purpose', undefined, 'medium'],
		])
		expect(recs[1].prompt).toContain(recs[0].prompt)

		const ctx2 = fakeCtx({ issue: 'bd-1' }, script({ record: null }))
		const got2 = await wf.run(ctx2)
		expect(got2).toMatchObject({ status: 'scored', recorded: false, reason: 'could not record: record agent failed' })
		expect(callsOf(ctx2, 'record').map((c) => c.label)).toEqual(['record', 'record@escalated'])
	})

	it('takes a well-formed ok:false from trace and record as their answer, without escalating', async () => {
		const wf = await load('score-issue', undefined)
		const ctx = fakeCtx({ issue: 'bd-1' }, script({ record: { ok: false, error: 'exit 7' } }))
		const got = await wf.run(ctx)
		expect(got).toMatchObject({ status: 'scored', recorded: false, reason: 'could not record: exit 7' })
		expect(callsOf(ctx, 'record').map((c) => c.label)).toEqual(['record'])
		expect(ctx.calls.some((c) => c.label.endsWith('@escalated'))).toBe(false)

		const ctx2 = fakeCtx({ issue: 'bd-1', dryRun: true }, script({ trace: { ok: false, summary: 'Work: partial', error: 'write refused' } }))
		const got2 = await wf.run(ctx2)
		expect(got2.work).toBe('Work: partial\n(Not stored as work metadata: write refused)')
		expect(callsOf(ctx2, 'trace').map((c) => c.label)).toEqual(['trace'])
		expect(ctx2.calls.some((c) => c.label.endsWith('@escalated'))).toBe(false)
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
