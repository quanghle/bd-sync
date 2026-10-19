// Per-run log files in .claude/workflows/plan-implement-review.js: every agent that runs cargo writes each command's
// output to its own file, <logDir>/<run>/<label>.log (reviewers to a mktemp file there, so a real reviewer and its shadows
// keep byte-identical prompts), and full suites go through the suite lock (.github/scripts/suite-lock.mjs). A workflow
// script isn't a module (top-level await and return), so this lifts the log helpers, the prompt builders and what they use
// out of the source, like the ops, record and shadow specs, and renders the prompts with a stub agent keyed by label.
import { execFileSync } from 'node:child_process'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
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
	slice('const SETUP =', 'const RECORD ='),
	slice('const CODER =', 'const TRIAGE ='),
	// Through TARGET_CMD, which the setup prompt names.
	slice('const SNAPSHOT_CMD =', 'let TARGET'),
	slice('const inDir =', '// ---------- logs'),
	slice('const logDirOf =', 'const TASK ='),
	slice('// ---------- logs', '// Areas whose AGENTS.md rules'),
	slice('const touchesEngine =', 'const dedupe ='),
	slice('const ledger = []', '// ---------- Setup'),
	slice('const setupPrompt =', 'const setup = await ops('),
	slice('// ---------- gate', '// ---------- bd record'),
	slice('const followUpKey =', '// A title as one'),
	slice('async function review(', '// Files approved findings'),
	slice('const stepCoderPrompt =', 'if (A.skipImplement)'),
	slice('const fixPrompt =', 'for (let round = 0'),
].join('\n')
const names = [
	'ops',
	'logDirOf',
	'LOG_DIR',
	'fnv1a',
	'safeId',
	'shPath',
	'RUN_ID',
	'tmpRootOf',
	'logFile',
	'SUITE_TEST',
	'logRule',
	'reviewLogRule',
	'setupPrompt',
	'gate',
	'gateFixPrompt',
	'gateUntilGreen',
	'followUpKey',
	'review',
	'validate',
	'stepCoderPrompt',
	'fixPrompt',
	'GATE',
	'SETUP',
	'markerOf',
	'normDir',
	'sameDir',
	'contamination',
	'contaminatedReason',
	'gateCmd',
	'gateRerunCmd',
	'gatePrompt',
]

const DIR = '/w/bd-x-1'
const ROOT = '/logs root'
const marker = (dir, run = 'bd-x.1') => `bd-gate: dir=${dir} run=${run}`
const PASSED = { passed: true, failures: [], snapshot: 'snap2', changedFiles: ['a.rs'], marker: marker(DIR) }
const LINT = { passed: false, failures: [{ command: 'cargo clippy', excerpt: 'unused variable' }], snapshot: 'snap1', changedFiles: ['a.rs'] }
const FOREIGN_REPORT = { ...PASSED, marker: marker('/w/other') }

/**
 * The workflow's helpers bound to args A and a stub agent that answers from replies[label] (null when missing); over
 * replaces any of the free variables (DIR, TARGET, ...).
 */
function load(A, replies = {}, over = {}) {
	const calls = []
	const logs = []
	const agent = async (prompt, opts) => {
		calls.push({ prompt, ...opts })
		return replies[opts.label] ?? null
	}
	const params = {
		A,
		REQ_TEXT: [A.requirements].flat().join('\n'),
		TASK: 'Requirements:\nmake it so',
		BASE: 'main',
		DIR,
		TARGET: '/repo/target/implement-review',
		setup: { baseline: 'base0' },
		plan: { summary: 's', requirements: [{ id: 'R1', text: 't', acceptance: 'a' }], steps: [], decisions: [] },
		done: [],
		SHADOWS: [{ model: 'sonnet', effort: 'medium' }],
		CODER_OPTS: {},
		REVIEW_OPTS: {},
		MAX_GATE_FIXES: 2,
		agent,
		log: (m) => logs.push(m),
		phase: () => {},
		renew: async () => {},
		parallel: (thunks) => Promise.all(thunks.map((t) => t())),
		pipeline: (items, fn) => Promise.all(items.map(fn)),
		...over,
	}
	const lifted = new Function(...Object.keys(params), `${body}; return { ${names.join(', ')}, logRoot: () => LOG_ROOT }`)(...Object.values(params))
	return { ...lifted, calls, logs }
}

const X = { issue: 'bd-x.1', requirements: 'make it so', logDir: `${ROOT}/` }
const POSIX = process.platform === 'win32' && 'no POSIX sh'
const shell = (script) => execFileSync('sh', ['-c', script], { encoding: 'utf8' })
const LOG_DIR_ERROR = /^args\.logDir must be an absolute directory without '\.\.' or control characters \(your scratchpad\), got /

describe('plan-implement-review logDirOf()', () => {
	const { logDirOf } = load(X)

	it('accepts an absolute directory and drops trailing slashes', () => {
		expect(logDirOf('/a/b')).toBe('/a/b')
		expect(logDirOf('/a/b/')).toBe('/a/b')
		expect(logDirOf('/logs root//')).toBe('/logs root')
		expect(logDirOf('/')).toBe('/')
		expect(logDirOf(undefined)).toBeNull()
		expect(logDirOf(null)).toBeNull()
	})

	it.each([
		['a relative path', 'rel'],
		['a .. segment', '/a/../b'],
		['a trailing .. segment', '/a/..'],
		['a newline', '/a\nb'],
		['a NUL character', `/a${String.fromCharCode(0)}b`],
		['a unit separator', `/a${String.fromCharCode(31)}b`],
		['a DEL character', '/a\u007fb'],
		['a number', 42],
		['an empty string', ''],
	])('throws on %s', (_, v) => {
		expect(() => logDirOf(v)).toThrow(LOG_DIR_ERROR)
	})

	it('keeps dots that are not a whole segment', () => {
		expect(logDirOf('/a/..b/c.')).toBe('/a/..b/c.')
	})

	it('validates args.logDir when the script starts', () => {
		expect(() => load({ ...X, logDir: 'scratch' })).toThrow('args.logDir must be')
		expect(load(X).LOG_DIR).toBe(ROOT)
		expect(load(X).logRoot()).toBe(ROOT)
	})
})

describe('plan-implement-review log paths', () => {
	it('names the run after the issue, made path-safe', () => {
		expect(load(X).RUN_ID).toBe('bd-x.1')
		expect(load({ ...X, issue: 'bd x/1' }).RUN_ID).toBe('bd-x-1')
	})

	it('names a run without an issue by a hash of its requirements and workdir', () => {
		const a = load({ requirements: 'a', workdir: '/w' }).RUN_ID
		expect(a).toMatch(/^run-[0-9a-f]{8}$/)
		expect(load({ requirements: 'a', workdir: '/w' }).RUN_ID).toBe(a)
		expect(load({ requirements: 'b', workdir: '/w' }).RUN_ID).not.toBe(a)
		expect(load({ requirements: 'a', workdir: '/v' }).RUN_ID).not.toBe(a)
		expect(load({ requirements: 'a' }).RUN_ID).not.toBe(a)
	})

	it('hashes with the same FNV-1a as followUpKey', () => {
		const { fnv1a, followUpKey } = load(X)
		for (const f of [
			{ file: 'a.rs', claim: 'c' },
			{ file: 'crates/bd-core/src/graph.rs', claim: 'déjà vu — 🦀 off by one' },
			{ file: '', claim: '' },
		]) {
			expect(followUpKey('bd-x.review', f)).toBe(`followup:bd-x.review/${fnv1a(`${f.file}\n${f.claim}`)}`)
		}
		expect(fnv1a('')).toBe('811c9dc5')
		expect(fnv1a('a')).toBe('e40c292c')
	})

	it('gives each label its own file', () => {
		const { logFile } = load(X)
		expect(logFile('gate:impl')).toBe(`${ROOT}/bd-x.1/gate-impl.log`)
		expect(logFile('gate:impl@sonnet').endsWith('/bd-x.1/gate-impl-sonnet.log')).toBe(true)
		expect(logFile('validate:r0:F1')).toBe(`${ROOT}/bd-x.1/validate-r0-F1.log`)
	})

	it('quotes a path as one shell word', { skip: POSIX }, () => {
		const { shPath } = load(X)
		for (const p of ['/logs root/x.log', "/it's/$(touch nope)/`x`.log"]) expect(shell(`printf %s ${shPath(p)}`)).toBe(p)
	})

	it('falls back to /tmp for a missing or invalid setup tmpdir', () => {
		const { tmpRootOf } = load(X)
		expect(tmpRootOf(undefined)).toBe('/tmp')
		expect(tmpRootOf('x/../y')).toBe('/tmp')
		expect(tmpRootOf('/a\nb')).toBe('/tmp')
		expect(tmpRootOf('/var/folders/T/')).toBe('/var/folders/T')
	})

	it('runs only the full suite through the lock, unlocked where the worktree has no lock script', () => {
		expect(load(X).SUITE_TEST).toBe(
			'if [ -f .github/scripts/suite-lock.mjs ]; then node .github/scripts/suite-lock.mjs --run bd-x.1 -- cargo test --workspace --locked; else cargo test --workspace --locked; fi',
		)
	})

	it('logRule names its file as one quoted word, the redirect without tee, and the suite lock', () => {
		const { logRule, SUITE_TEST } = load(X)
		const rule = logRule('coder:S1')
		const word = `'${ROOT}/bd-x.1/coder-S1.log'`
		expect(rule).toContain(`write the full output of every cargo command you run to ${word} only`)
		expect(rule).toContain(`mkdir -p '${ROOT}/bd-x.1'`)
		expect(rule).toContain(`> ${word} 2>&1; echo "exit=$?"`)
		expect(rule).toContain('do not pipe a command into tee')
		expect(rule).toContain(SUITE_TEST)
		expect(rule).toContain('exit 75')
		expect(rule).toContain('`cargo test -p <crate> [filter]`) run without the lock')
		expect(rule).toContain('cargo fmt, cargo clippy')
		expect(rule).not.toContain('\n')
	})

	it('reviewLogRule gives each reviewer a mktemp file and names no label or model', () => {
		const { reviewLogRule, SUITE_TEST } = load(X)
		const rule = reviewLogRule('code', 0)
		expect(rule).toContain(`mkdir -p '${ROOT}/bd-x.1' && f=$(mktemp '${ROOT}/bd-x.1/review-code-r0.XXXXXX')`)
		expect(rule).toContain('<command> > "$f" 2>&1; echo "log=$f exit=$?"')
		expect(rule).toContain(SUITE_TEST)
		expect(rule).toContain('exit 75')
		expect(rule).toContain('`cargo test -p <crate> [filter]`) run without the lock')
		for (const no of ['@shadow', 'sonnet', 'haiku', 'opus', 'review:code', '\n']) expect(rule).not.toContain(no)
		expect(reviewLogRule('security', 2)).toContain('/review-security-r2.XXXXXX')
	})

	it('reviewLogRule runs as written and gives two reviewers two files', { skip: POSIX }, () => {
		const root = mkdtempSync(join(tmpdir(), 'pir logs '))
		try {
			const { reviewLogRule } = load({ ...X, logDir: root })
			const cmd = reviewLogRule('code', 0).match(/`([^`]*mktemp[^`]*)`/)[1].replace('<command>', 'echo hi')
			const runs = [shell(cmd), shell(cmd)].map((out) => out.trim().match(/^log=(.*) exit=0$/)?.[1])
			expect(runs[0]).toBeTruthy()
			expect(runs[1]).toBeTruthy()
			expect(runs[0]).not.toBe(runs[1])
			for (const f of runs) {
				expect(f.startsWith(join(root, 'bd-x.1', 'review-code-r0.'))).toBe(true)
				expect(readFileSync(f, 'utf8')).toBe('hi\n')
			}
		} finally {
			rmSync(root, { recursive: true, force: true })
		}
	})
})

describe('plan-implement-review setup', () => {
	const NO_DIR = { issue: 'bd-x.1', requirements: 'make it so' }

	it('asks for TMPDIR only without logDir, in every branch', () => {
		for (const A of [{}, { workdir: '/w' }, { workdir: '/w', baseline: 'abc' }]) {
			const without = load({ ...NO_DIR, ...A })
			expect(without.logRoot()).toBe('')
			const prompt = without.setupPrompt()
			expect(prompt).toContain('Also run `printf %s "${TMPDIR:-/tmp}"` and return its output as tmpdir.')
			expect(prompt).toContain('/target/implement-review')
			expect(load({ ...X, ...A }).setupPrompt()).not.toContain('tmpdir')
		}
	})

	it('keeps the setup report compatible', () => {
		const { SETUP } = load(X)
		expect(SETUP.required).toEqual(['workdir', 'baseline', 'target'])
		expect(typeof SETUP.properties.tmpdir.type).toBe('string')
		expect(SETUP.properties.tmpdir.type).toBe('string')
	})
})

/** Renders every prompt that runs cargo, through the code paths the workflow uses. */
async function render() {
	const w = load(X, {
		'gate:impl': LINT,
		'coder:gate-fix:impl:1': { summary: 'fixed lint', filesChanged: ['a.rs'] },
		'gate:impl:1': PASSED,
		'review:code:r0': { findings: [] },
	})
	expect(await w.gateUntilGreen('impl', 0)).toBe(PASSED)
	await w.review(0, 'snap2', ['crates/bd-core/src/graph.rs'], 'base0', [])
	await w.validate([{ file: 'a.rs', line: 1, severity: 'serious', category: 'correctness', claim: 'c', evidence: 'e' }], 'r0', 'snap2')
	const work = [{ f: { id: 'F1', file: 'a.rs', severity: 'serious', category: 'c', claim: 'c', evidence: 'e' }, d: { instruction: 'do it' } }]
	const prompts = {
		...Object.fromEntries(w.calls.map((c) => [c.label, c.prompt])),
		'coder:S1': w.stepCoderPrompt({ id: 'S1', title: 't', approach: 'a', tests: 't' }, 'coder:S1'),
		'coder:fix:r1': w.fixPrompt(work, 'coder:fix:r1'),
	}
	return { w, prompts }
}

describe('plan-implement-review prompts name their own log file', () => {
	const LABELS = ['coder:S1', 'coder:gate-fix:impl:1', 'coder:fix:r1', 'validate:r0:F1']
	const logPaths = (prompt) => new Set(prompt.match(/\/logs root\/[^'"]*\.log/g) ?? [])

	it('runs the gate fix under its own label', async () => {
		const { w } = await render()
		expect(w.calls.slice(0, 3).map((c) => c.label)).toEqual(['gate:impl', 'coder:gate-fix:impl:1', 'gate:impl:1'])
	})

	it.each(LABELS)('%s names exactly its own file, single-quoted, and the suite lock', async (label) => {
		const { w, prompts } = await render()
		const prompt = prompts[label]
		expect(typeof prompt).toBe('string')
		const own = w.logFile(label)
		expect(logPaths(prompt)).toEqual(new Set([own]))
		expect(prompt).toContain(`'${own}'`)
		expect(prompt.endsWith(w.logRule(label))).toBe(true)
		expect(prompt).toContain(w.SUITE_TEST)
	})

	it('gives every agent that runs cargo a distinct file under the run directory', async () => {
		const { w } = await render()
		const all = ['gate:impl', 'gate:impl@sonnet', 'gate:impl:1', ...LABELS]
		const paths = all.map((l) => w.logFile(l))
		expect(new Set(paths).size).toBe(all.length)
		for (const p of paths) expect(p.startsWith(`${ROOT}/bd-x.1/`)).toBe(true)
	})

	it('gives a real reviewer and its shadow the same prompt, ending with its kind and round rule', async () => {
		const { w, prompts } = await render()
		for (const kind of ['code', 'requirements', 'invariants']) {
			const real = prompts[`review:${kind}:r0`]
			expect(typeof real).toBe('string')
			expect(prompts[`review:${kind}:r0@shadow:sonnet-medium`]).toBe(real)
			expect(real.endsWith(`\n\n${w.reviewLogRule(kind, 0)}`)).toBe(true)
			expect(logPaths(real)).toEqual(new Set())
		}
	})
})

/** One gate() call over the given replies, with the labels it asked for. */
async function gateOnce(replies) {
	const w = load(X, replies)
	return { w, g: await w.gate('gate:impl'), labels: w.calls.map((c) => c.label) }
}

describe('plan-implement-review contaminated gate', () => {
	const FOREIGN = { ...PASSED, marker: marker('/w/other') }
	const WRONG_RUN = { ...PASSED, marker: marker(DIR, 'bd-y.2') }

	it('parses the bd-gate marker', () => {
		const { markerOf } = load(X)
		expect(markerOf('bd-gate: dir=/w/a b run=bd-x.1')).toEqual({ dir: '/w/a b', run: 'bd-x.1' })
		expect(markerOf('  bd-gate: dir=/w/a run=bd-x.1 \n')).toEqual({ dir: '/w/a', run: 'bd-x.1' })
		expect(markerOf('bd-gate: dir= run=')).toEqual({ dir: '', run: '' })
		expect(markerOf('bd-gate: dir=/w/a')).toBeNull()
		expect(markerOf('warning: bd-gate: dir=/w/a run=bd-x.1')).toBeNull()
		expect(markerOf('bd-gate: dir=/w/a run=bd x')).toBeNull()
		expect(markerOf('')).toBeNull()
		expect(markerOf(undefined)).toBeNull()
	})

	it('compares directories ignoring a trailing slash and /private', () => {
		const { sameDir } = load(X)
		expect(sameDir('/private/var/x/', '/var/x')).toBe(true)
		expect(sameDir('/var/x', '/private/var/x')).toBe(true)
		expect(sameDir('/var/x', '/var/y')).toBe(false)
		expect(sameDir('', '')).toBe(false)
		expect(sameDir('/privatefoo/x', '/foo/x')).toBe(false)
	})

	it('classifies reports', () => {
		const { contamination } = load(X)
		expect(contamination(PASSED, DIR, 'bd-x.1')).toBeNull()
		expect(contamination({ ...PASSED, marker: marker(`/private${DIR}/`) }, DIR, 'bd-x.1')).toBeNull()
		expect(contamination(FOREIGN, DIR, 'bd-x.1')).toEqual({ dir: '/w/other', run: 'bd-x.1', marker: marker('/w/other') })
		expect(contamination(WRONG_RUN, DIR, 'bd-x.1')).toEqual({ dir: DIR, run: 'bd-y.2', marker: marker(DIR, 'bd-y.2') })
		expect(contamination({ ...PASSED, marker: 'garbage' }, DIR, 'bd-x.1')).toEqual({ dir: '', run: '', marker: 'garbage' })
		expect(contamination({ ...PASSED, marker: undefined }, DIR, 'bd-x.1')).toEqual({ dir: '', run: '', marker: '' })
		expect(contamination({ ...PASSED, marker: '  ' }, DIR, 'bd-x.1')).toEqual({ dir: '', run: '', marker: '' })
		expect(contamination(LINT, DIR, 'bd-x.1')).toBeNull()
		expect(contamination({ ...LINT, marker: marker(DIR) }, DIR, 'bd-x.1')).toBeNull()
		expect(contamination({ ...LINT, marker: marker('/w/other') }, DIR, 'bd-x.1')).toEqual({ dir: '/w/other', run: 'bd-x.1', marker: marker('/w/other') })
	})

	it('explains a contaminated gate', () => {
		const { contaminatedReason } = load(X)
		const log = '/logs root/bd-x.1/gate-impl-sonnet.log'
		expect(contaminatedReason({ contaminated: true, marker: marker('/w/other'), log }, DIR, 'bd-x.1')).toBe(
			`gate log contaminated: its marker says "bd-gate: dir=/w/other run=bd-x.1", expected dir=${DIR} run=bd-x.1 (log ${log})`,
		)
		expect(contaminatedReason({ contaminated: true, marker: '', log }, DIR, 'bd-x.1')).toBe(
			`gate log contaminated: no bd-gate marker although the gate passed, expected dir=${DIR} run=bd-x.1 (log ${log})`,
		)
	})

	it.each([
		['a matching marker', marker(DIR)],
		['/private and a trailing slash', marker(`/private${DIR}/`)],
	])('passes %s in one call', async (_, m) => {
		const report = { ...PASSED, marker: m }
		const { g, labels } = await gateOnce({ 'gate:impl': report })
		expect(g).toBe(report)
		expect(labels).toEqual(['gate:impl'])
	})

	it.each([
		['a foreign directory', FOREIGN, '/w/other'],
		['a foreign run', WRONG_RUN, DIR],
	])('escalates %s once, then returns the contaminated marker', async (_, report, dir) => {
		const { w, g, labels } = await gateOnce({ 'gate:impl': report, 'gate:impl@sonnet': report })
		expect(labels).toEqual(['gate:impl', 'gate:impl@sonnet'])
		expect(g).toMatchObject({ contaminated: true, dir, marker: report.marker })
		expect(g.passed).toBeUndefined()
		expect(g.log).toBe(`${ROOT}/bd-x.1/gate-impl-sonnet.log`)
		expect(w.logs).toContain(`gate gate:impl: log contaminated (${report.marker})`)
		expect(w.logs).toContain(`gate gate:impl@sonnet: log contaminated (${report.marker})`)
	})

	it('accepts a clean sonnet report after a foreign haiku one', async () => {
		const { g, labels } = await gateOnce({ 'gate:impl': FOREIGN, 'gate:impl@sonnet': PASSED })
		expect(g).toBe(PASSED)
		expect(labels).toEqual(['gate:impl', 'gate:impl@sonnet'])
	})

	it('treats a pass without a marker as contaminated', async () => {
		const bare = { ...PASSED, marker: '' }
		const { w, g } = await gateOnce({ 'gate:impl': bare, 'gate:impl@sonnet': { ...PASSED, marker: undefined } })
		expect(g).toMatchObject({ contaminated: true, dir: '', run: '', marker: '' })
		expect(w.logs).toContain('gate gate:impl@sonnet: log contaminated (no marker)')
	})

	it('treats a garbled marker as contaminated', async () => {
		const garbled = { ...PASSED, marker: 'error: could not compile' }
		const { g } = await gateOnce({ 'gate:impl': garbled, 'gate:impl@sonnet': garbled })
		expect(g).toMatchObject({ contaminated: true, marker: 'error: could not compile' })
	})

	it('reports only the last attempt: a schema failure after contamination is a failed gate agent', async () => {
		const { g } = await gateOnce({ 'gate:impl': FOREIGN, 'gate:impl@sonnet': null })
		expect(g).toBeNull()
	})

	it('returns a lint failure without a marker as a normal failure in one call', async () => {
		const { g, labels } = await gateOnce({ 'gate:impl': LINT })
		expect(g).toBe(LINT)
		expect(labels).toEqual(['gate:impl'])
	})

	it('never sends a contaminated gate to the gate-fix coder', async () => {
		const w = load(X, { 'gate:impl': FOREIGN, 'gate:impl@sonnet': FOREIGN })
		const g = await w.gateUntilGreen('impl', 0)
		expect(g.contaminated).toBe(true)
		expect(w.calls.map((c) => c.label)).toEqual(['gate:impl', 'gate:impl@sonnet'])
	})

	it('stops the gate-fix loop when a later gate is contaminated', async () => {
		const w = load(X, {
			'gate:impl': LINT,
			'coder:gate-fix:impl:1': { summary: 'fixed lint', filesChanged: ['a.rs'] },
			'gate:impl:1': FOREIGN,
			'gate:impl:1@sonnet': FOREIGN,
		})
		const g = await w.gateUntilGreen('impl', 0)
		expect(g.contaminated).toBe(true)
		expect(w.calls.map((c) => c.label)).toEqual(['gate:impl', 'coder:gate-fix:impl:1', 'gate:impl:1', 'gate:impl:1@sonnet'])
	})

	it('sends a lint failure to the gate-fix coder once before gating again', async () => {
		const w = load(X, { 'gate:impl': LINT, 'coder:gate-fix:impl:1': { summary: 'fixed lint', filesChanged: ['a.rs'] }, 'gate:impl:1': PASSED })
		expect(await w.gateUntilGreen('impl', 0)).toBe(PASSED)
		expect(w.calls.map((c) => c.label)).toEqual(['gate:impl', 'coder:gate-fix:impl:1', 'gate:impl:1'])
	})

	it('escalates a contaminated gate at both call sites before checking passed', () => {
		const sites = [...source.matchAll(/await gateUntilGreen\(/g)].map((m) => m.index)
		expect(sites).toHaveLength(2)
		for (const at of sites) {
			const rest = source.slice(at)
			const contaminated = rest.indexOf("if (g.contaminated) return result('escalated', { reason: contaminatedReason(g, DIR, RUN_ID)")
			const passed = rest.indexOf('.passed')
			expect(contaminated).toBeGreaterThan(0)
			expect(contaminated).toBeLessThan(passed)
		}
	})

	it('keeps the gate report fields required', () => {
		const { GATE } = load(X)
		expect(GATE.required).toEqual(['passed', 'failures', 'snapshot', 'changedFiles'])
		expect(GATE.properties.log).toMatchObject({ type: 'string' })
		expect(GATE.properties.marker).toMatchObject({ type: 'string' })
	})
})

describe('plan-implement-review gate command', () => {
	const LOG = `'${ROOT}/bd-x.1/gate-impl.log'`

	it('writes the marker first, then fmt, clippy and the locked suite into its own log', () => {
		const { gateCmd, SUITE_TEST } = load(X)
		const cmd = gateCmd('gate:impl')
		expect(cmd.startsWith(`mkdir -p '${ROOT}/bd-x.1' && cd '${DIR}' && { echo "bd-gate: dir=$PWD run=bd-x.1"; export CARGO_TARGET_DIR='/repo/target/implement-review'; `)).toBe(true)
		expect(cmd).toContain('cargo fmt --all --check; echo "exit[fmt]=$?"; cargo clippy --workspace --all-targets --locked -- -D warnings; echo "exit[clippy]=$?"; ')
		expect(cmd).toContain(`${SUITE_TEST}; echo "exit[test]=$?"; } > ${LOG} 2>&1; grep '^exit\\[' ${LOG}`)
		// Only the full suite takes the lock.
		expect(cmd.split('suite-lock.mjs --run').length).toBe(2)
		expect(cmd).not.toContain('tee')
	})

	it('reruns only the suite, appending to the same log', () => {
		const { gateRerunCmd, SUITE_TEST } = load(X)
		expect(gateRerunCmd('gate:impl')).toBe(
			`cd '${DIR}' && { export CARGO_TARGET_DIR='/repo/target/implement-review'; ${SUITE_TEST}; echo "exit[test]=$?"; } >> ${LOG} 2>&1; grep '^exit\\[test\\]' ${LOG} | tail -1`,
		)
	})

	it('asks for the command, the rerun on exit 75, the log and the marker', () => {
		const { gatePrompt, gateCmd, gateRerunCmd } = load(X)
		const prompt = gatePrompt('gate:impl')
		expect(prompt).toContain(gateCmd('gate:impl'))
		expect(prompt).toContain('echo "bd-gate: dir=$PWD run=bd-x.1"')
		expect(prompt).toContain('exit[test]=75')
		expect(prompt).toContain(gateRerunCmd('gate:impl'))
		expect(prompt).toContain(`>> ${LOG} 2>&1`)
		expect(prompt).toContain('600000')
		expect(prompt).toContain(`head -1 ${LOG}`)
		expect(prompt).toContain(`Return ${LOG} as "log"`)
		expect(prompt).toContain('verbatim as "marker"')
		expect(prompt).toContain('git diff --name-only base0 <snapshot>')
		expect(prompt).toContain('Do NOT fix anything')
	})

	it.each(['gate:impl', 'gate:impl@sonnet', 'gate:impl:1'])('the %s prompt names exactly its own file', async (label) => {
		const w = load(X, { 'gate:impl': FOREIGN_REPORT, 'gate:impl@sonnet': PASSED })
		const prompt = w.gatePrompt(label)
		const own = w.logFile(label)
		expect(new Set(prompt.match(/\/logs root\/[^'"]*\.log/g))).toEqual(new Set([own]))
		expect(prompt).toContain(`'${own}'`)
	})

	it('asks each attempt for its own log: the retry renders under its own label', async () => {
		const { w } = await gateOnce({ 'gate:impl': FOREIGN_REPORT, 'gate:impl@sonnet': PASSED })
		const [first, retry] = w.calls
		expect(first.prompt).toContain(`'${w.logFile('gate:impl')}'`)
		expect(retry.label).toBe('gate:impl@sonnet')
		expect(retry.prompt).toContain(`'${w.logFile('gate:impl@sonnet')}'`)
		expect(retry.prompt).not.toContain(`'${w.logFile('gate:impl')}'`)
	})

	it('runs under sh and zsh with a fake cargo, unlocked without the script and locked with it', { skip: POSIX, timeout: 30_000 }, () => {
		const tmp = mkdtempSync(join(tmpdir(), 'pir gate '))
		try {
			const dir = join(tmp, "work it's")
			const target = join(tmp, 'target')
			const bin = join(tmp, 'bin')
			const logs = join(tmp, 'logs')
			for (const d of [dir, target, bin]) mkdirSync(d)
			// Echoes its arguments, says whether the suite lock is held, and fails clippy only.
			writeFileSync(
				join(bin, 'cargo'),
				'#!/bin/sh\necho "cargo $* target=$CARGO_TARGET_DIR"\n[ -f .git/bd-suite.lock/owner.json ] && echo "lock held"\n[ "$1" = clippy ] && exit 1\nexit 0\n',
			)
			chmodSync(join(bin, 'cargo'), 0o755)
			const env = { ...process.env, PATH: `${bin}:${dirname(process.execPath)}:${process.env.PATH}` }
			const w = load({ ...X, logDir: logs }, {}, { DIR: dir, TARGET: target })
			const cmd = w.gateCmd('gate:impl')
			const file = w.logFile('gate:impl')
			const shells = ['sh']
			try {
				execFileSync('sh', ['-c', 'command -v zsh'], { stdio: 'ignore' })
				shells.push('zsh')
			} catch {}
			const run = (sh) => {
				const out = execFileSync(sh, ['-c', cmd], { encoding: 'utf8', env })
				const log = readFileSync(file, 'utf8')
				const first = log.split('\n')[0]
				const m = w.markerOf(first)
				expect(m).toBeTruthy()
				expect(w.sameDir(m.dir, dir)).toBe(true)
				expect(m.run).toBe('bd-x.1')
				expect(out).toBe('exit[fmt]=0\nexit[clippy]=1\nexit[test]=0\n')
				expect(log).toContain(`cargo clippy --workspace --all-targets --locked -- -D warnings target=${target}`)
				expect(log).toContain('cargo test --workspace --locked')
				return log
			}
			for (const sh of shells) expect(run(sh)).not.toContain('lock held')
			// A worktree that has the lock script runs the suite through it, and leaves no lock behind.
			execFileSync('git', ['init', '-q', dir])
			mkdirSync(join(dir, '.github', 'scripts'), { recursive: true })
			copyFileSync(fileURLToPath(new URL('./suite-lock.mjs', import.meta.url)), join(dir, '.github', 'scripts', 'suite-lock.mjs'))
			for (const sh of shells) {
				expect(run(sh)).toContain('lock held')
				expect(existsSync(join(dir, '.git', 'bd-suite.lock'))).toBe(false)
			}
			// The rerun appends one more exit[test] line.
			const again = execFileSync('sh', ['-c', w.gateRerunCmd('gate:impl')], { encoding: 'utf8', env })
			expect(again).toBe('exit[test]=0\n')
			expect(readFileSync(file, 'utf8').match(/^exit\[test\]=/gm)).toHaveLength(2)
		} finally {
			rmSync(tmp, { recursive: true, force: true })
		}
	})
})
