// The coder's limits in plan-implement-review's planner prompts (.claude/workflows/plan-implement-review.js and the Copilot
// extension .github/extensions/plan-implement-review/extension.mjs): CODER_WORK, right after inDir, states what the coder
// may not do (inDir's own limits), and the draft planner, the plan critic and triage keep work outside it out of steps and
// fixes, since the workflow never hands work to the controller or a person. Neither harness is a module (top-level await
// and return, or one async run(ctx)), so this checks their prompt source text and evaluates the inDir .. readOnly slice,
// like the logs and shadow specs.
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
