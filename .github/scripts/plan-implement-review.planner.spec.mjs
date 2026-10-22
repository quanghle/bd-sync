// The coder's limits in plan-implement-review's planner prompts (.claude/workflows/plan-implement-review.js and the Copilot
// extension .github/extensions/plan-implement-review/extension.mjs): CODER_WORK, right after inDir, states what the coder
// may not do (inDir's own limits), and the draft planner, the plan critic and triage keep work outside it out of steps and
// fixes, since the workflow never hands work to the controller or a person. Neither harness is a module (top-level await
// and return, or one async run(ctx)), so this checks their prompt source text and evaluates the inDir .. readOnly slice,
// like the logs and shadow specs.
// It also covers args.plannerEffort: effortOf checks it (default high), PLANNER_EFFORT sets the effort of the
// planner-role agents (planner draft, critic, final, revise, triage), and validators stay high. The Plan and Triage
// stages are top-level code, so their call sites are checked against the source text.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from './expect.mjs'

const CLAUDE = 'plan-implement-review.js'
const HARNESSES = [
	[CLAUDE, '../../.claude/workflows/plan-implement-review.js'],
	['extension.mjs', '../extensions/plan-implement-review/extension.mjs'],
]

const read = (p) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), 'utf8')
const slice = (source, from, to) => {
	const i = source.indexOf(from)
	const j = i < 0 ? -1 : source.indexOf(to, i)
	if (i < 0 || j < 0) throw new Error(`no longer has ${i < 0 ? from : to} (slice ${from} … ${to})`)
	return source.slice(i, j)
}
// inDir and CODER_WORK from a harness, with TARGET (a let declared before the slice) supplied.
const limits = (source) => new Function('TARGET', `${slice(source, 'const inDir =', 'const readOnly =')}; return { inDir, CODER_WORK }`)('/w/target')

// What CODER_WORK names.
const CODER_WORK_NEEDLES = [
	'coder',
	'worktree',
	'commit',
	'branch',
	'merge',
	'rebase',
	'push',
	'CI on GitHub',
	'.claude/settings.json',
	'hook entries',
	'plugins/bd/hooks/',
	'.git/',
	'.env',
	'new Cargo or npm dependencies',
	'controller or a person',
]
// Every limit CODER_WORK names that inDir, which the coder reads, must name too.
const SHARED = [
	'commit',
	'merge',
	'rebase',
	'push',
	'CI on GitHub',
	'branch',
	'.claude/settings.json',
	'hook entries',
	'plugins/bd/hooks/',
	'.git/',
	'.env',
	'new Cargo or npm dependencies',
]

describe.each(HARNESSES)('%s', (name, path) => {
	const source = read(path)

	it('defines CODER_WORK between inDir and readOnly', () => {
		const at = source.indexOf('const CODER_WORK =')
		expect(at > source.indexOf('const inDir =') && source.indexOf('const inDir =') >= 0).toBe(true)
		expect(at < source.indexOf('const readOnly =')).toBe(true)
		// The logs spec evaluates the Claude workflow's inDir .. logs slice, so CODER_WORK must sit inside it.
		if (name === CLAUDE) expect(at < source.indexOf('// ---------- logs')).toBe(true)
	})

	it("states the coder's limits", () => {
		const { CODER_WORK } = limits(source)
		expect(typeof CODER_WORK).toBe('string')
		for (const n of CODER_WORK_NEEDLES) expect(CODER_WORK, n).toContain(n)
	})

	it.each(SHARED)('names %s in both inDir and CODER_WORK', (needle) => {
		const { inDir, CODER_WORK } = limits(source)
		expect(inDir('/w')).toContain(needle)
		expect(CODER_WORK).toContain(needle)
	})

	it('leaves the gate agents their local checks', () => {
		const text = limits(source).inDir('/w')
		expect(text).toContain('local cargo checks these instructions name are fine')
		expect(text).not.toContain('run CI')
		expect(text).not.toContain('no CI')
		// The gate prompt opens with inDir: if that ever changes, so may what inDir's CI clause must allow.
		expect(source).toContain('${inDir(DIR)}\\nRun the CI gates there')
	})

	it('keeps controller or person work out of plan steps', () => {
		const intro = slice(source, 'const planIntro =', 'const badPlan')
		expect(intro).toMatch(/\$\{CODER_WORK\}/)
		expect(intro).toContain('goes in "risks", never in a step')
		expect(intro).toContain('controller or a person')
	})

	it('has the critic block a step outside the coder limits', () => {
		const critic = slice(source, 'You are the plan critic', 'planner:critic')
		expect(critic).toMatch(/\$\{CODER_WORK\}/)
		const blocking = slice(critic, 'Blocking issues only:', 'approved=true if nothing blocks')
		expect(blocking).toContain('a step assigned to the controller or a person')
		expect(blocking).toContain("outside the coder's limits")
	})

	it('has triage escalate a fix outside the coder limits', () => {
		const triage = slice(source, 'const triage =', '// ---------- Implement')
		expect(triage).toMatch(/\$\{CODER_WORK\}/)
		const escalate = triage.split('\n').find((l) => l.includes('- escalate:'))
		expect(escalate, 'the escalate line').toBeTruthy()
		expect(escalate).toContain("outside the coder's limits")
		expect(escalate).toContain('controller or a person')
		expect(escalate).toContain('"reason"')
		expect(triage).toContain('Never write such work into a fix or amend instruction')
	})
})

// AGENTS.md: a change to one workflow's behavior is made in both harnesses' versions; equal text keeps them from drifting.
describe('both harnesses', () => {
	it('state the same limits', () => {
		const [claude, extension] = HARNESSES.map(([, path]) => limits(read(path)))
		expect(extension.CODER_WORK).toBe(claude.CODER_WORK)
		expect(extension.inDir('/w')).toBe(claude.inDir('/w'))
	})
})

describe('plan-implement-review.js plannerEffort', () => {
	const claude = read(HARNESSES[0][1])
	// EFFORTS (from the shadow slice, without A) and the effortOf .. logDir slice, which reads A.plannerEffort.
	const loadEffort = (A) =>
		new Function(
			'A',
			`${slice(claude, 'const EFFORTS =', 'const shadowsOf =')}\n${slice(claude, 'const effortOf =', '// args.logDir')}; return { effortOf, PLANNER_EFFORT }`,
		)(A)

	it('defaults to high', () => {
		expect(loadEffort({}).PLANNER_EFFORT).toBe('high')
		expect(loadEffort({ plannerEffort: null }).PLANNER_EFFORT).toBe('high')
	})

	it.each(['low', 'medium', 'high', 'xhigh', 'max'])('takes %s', (e) => {
		expect(loadEffort({ plannerEffort: e }).PLANNER_EFFORT).toBe(e)
	})

	it.each([['huge'], ['HIGH'], [''], [3], [{ effort: 'medium' }]])('throws for %j', (v) => {
		expect(() => loadEffort({ plannerEffort: v })).toThrow(/args\.plannerEffort must be one of low\|medium\|high\|xhigh\|max, got /)
	})

	it('names the value it refuses', () => {
		expect(() => loadEffort({ plannerEffort: 'huge' })).toThrow('args.plannerEffort must be one of low|medium|high|xhigh|max, got "huge"')
	})

	it('documents the arg', () => {
		const m = claude.match(/^export const meta = (\{[\s\S]*?\n\})/m)
		expect(m, 'meta').toBeTruthy()
		const meta = new Function(`return ${m[1]}`)()
		expect(meta.whenToUse).toContain('plannerEffort?')
		expect(meta.whenToUse).toContain('plannerEffort the planner, critic and triage agents')
		expect(claude).toContain('// - plannerEffort')
	})
})

// The lines that name a planner-role agent's label, in source order.
const callSites = (source) => source.split('\n').filter((l) => /label: ['"`]planner:/.test(l))

describe.each(HARNESSES)('plannerEffort call sites in %s', (name, path) => {
	const source = read(path)

	it('runs the five planner-role agents at PLANNER_EFFORT', () => {
		const lines = callSites(source)
		expect(lines.map((l) => l.match(/label: ['"`](planner:[a-z]+)/)[1])).toEqual([
			'planner:draft',
			'planner:critic',
			'planner:final',
			'planner:revise',
			'planner:triage',
		])
		for (const l of lines) {
			expect(l).toContain('effort: PLANNER_EFFORT')
			expect(l).not.toMatch(/effort: ['"]/)
		}
		// No other agent (coder, reviewer, shadow, mechanical) gets it.
		expect((source.match(/effort: PLANNER_EFFORT/g) ?? []).length).toBe(5)
	})

	it('keeps validators at high', () => {
		const validators = source.split('\n').filter((l) => l.includes('schema: VERDICT'))
		expect(validators.length >= 1).toBe(true)
		for (const l of validators) expect(l).toMatch(/effort: ['"]high['"]/)
	})

	it('logs a planner effort other than high', () => {
		expect(source).toContain('Planner effort: ${PLANNER_EFFORT} (planner, critic, triage; validators stay high)')
		expect(source).toMatch(/PLANNER_EFFORT !== ['"]high['"]/)
	})

	if (name !== CLAUDE) {
		it('keeps the critic on the rubber-duck agent', () => {
			const critic = callSites(source).filter((l) => /label: ['"`]planner:critic/.test(l))
			expect(critic.length).toBe(1)
			expect(critic[0]).toContain('kind: "rubber-duck"')
		})
	}
})
