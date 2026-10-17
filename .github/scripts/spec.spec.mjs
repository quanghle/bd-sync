import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import { execFileSync } from 'node:child_process'
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MAX_DEPTH, ancestors, findSpecs, parseArgs, renderSpec, specView, specViews } from './spec.mjs'

const spec = { id: 's', title: 'Spec: labels', description: 'Labels on issues.', status: 'pinned', labels: ['spec', 'area:labels'] }
const req = (id, title, { status = 'pinned', labels = [], deps = [], created_at = `2026-10-15T00:00:0${id.at(-1)}Z`, ...rest } = {}) => ({
	id,
	title,
	status,
	created_at,
	labels: ['requirement', ...labels],
	parent: id.split('.').slice(0, -1).join('.') || null,
	dependencies: deps.map(([type, to]) => ({ id: to, type })),
	...rest,
})
const children = [
	req('s.3', 'Labels are case-insensitive', { deps: [['related', 'bd-w2']] }),
	req('s.1', 'Labels can be set at create', { deps: [['related', 'bd-w1']], description: 'With -l.\nRepeatable.' }),
	req('s.2', 'Labels are case-sensitive', { status: 'closed', deps: [['supersedes', 's.3'], ['related', 'bd-w1']], close_reason: 'superseded by s.3' }),
	{ ...req('s.4', 'No label hierarchy'), labels: ['non-goal'] },
	req('s.7', 'Labels show in brief output‮', { status: 'open' }),
	req('s.5', 'Labels have colours', { status: 'closed', close_reason: 'Removed: dropped in bd-w3\u001b[31m' }),
	{ id: 's.6', title: 'Not a requirement', status: 'closed', labels: [], parent: 's' },
]

// Checkout (c) holds Cart (c.1) and Payment (c.2), which holds Saved cards (c.2.1); Receipts (r) is another spec of
// the same area. Each spec's requirements are its children labelled requirement or non-goal.
const sp = (id, title, parent = null) => ({ id, title, parent, status: 'pinned', labels: ['spec', 'area:checkout'] })
const tree = [
	sp('c', 'Checkout'),
	req('c.9', 'Requires sign-in'),
	{ ...req('c.8', 'No guest checkout'), labels: ['non-goal'] },
	sp('c.1', 'Cart', 'c'),
	req('c.1.9', 'Shows the total'),
	sp('c.2', 'Payment', 'c'),
	req('c.2.9', 'Accepts cards'),
	sp('c.2.1', 'Saved cards', 'c.2'),
	req('c.2.1.9', 'Lists saved cards'),
	{ ...sp('c.3', 'Old page', 'c'), status: 'closed' },
	sp('r', 'Receipts'),
]
const isSpecIssue = (i) => (i.labels ?? []).includes('spec')
const sourceOf = (issues) => {
	const byId = new Map(issues.map((i) => [i.id, i]))
	return { get: (id) => byId.get(id), kids: (id) => issues.filter((i) => i.parent === id).map((i) => i.id) }
}

describe('findSpecs', () => {
	const other = { ...spec, id: 'o', labels: ['spec', 'area:query'] }
	it('finds a spec by id, or every open spec of an area in id order', () => {
		expect(findSpecs([spec, other], 'o')).toEqual([other])
		expect(findSpecs([spec, other], 'labels')).toEqual([spec])
		const t = { ...spec, id: 't' }
		expect(findSpecs([t, spec, { ...spec, id: 'u', status: 'closed' }], 'labels')).toEqual([spec, t])
	})
	it('refuses an unknown area', () => {
		expect(() => findSpecs([spec], 'nope')).toThrow(/no spec nope/)
	})
})

describe('specView', () => {
	const view = specView(spec, children)
	it('lists the requirements in force in creation order, with their sources', () => {
		expect(view.requirements.map((r) => [r.id, r.sources])).toEqual([
			['s.1', ['bd-w1']],
			['s.3', ['bd-w2']],
			['s.7', []],
		])
		expect(view.nonGoals.map((r) => r.id)).toEqual(['s.4'])
	})
	it('warns about a requirement that is neither pinned nor closed, direction controls dropped', () => {
		expect(view.warnings).toEqual(['s.7 is open, not pinned: pin it (bd update s.7 --status pinned) or close it'])
		expect(view.requirements.at(-1).title).toBe('Labels show in brief output')
		expect(renderSpec(view)).toContain('> Warning: s.7 is open')
	})
	it('keeps closed requirements as history: superseded or removed, control characters dropped', () => {
		expect(view.history.map(({ id, outcome, by, reason }) => ({ id, outcome, by, reason }))).toEqual([
			{ id: 's.2', outcome: 'superseded', by: 's.3', reason: 'superseded by s.3' },
			{ id: 's.5', outcome: 'removed', by: null, reason: 'Removed: dropped in bd-w3[31m' },
		])
	})
})

describe('specViews', () => {
	const source = sourceOf(tree)
	const ids = (views) => views.map((v) => [v.spec.id, ids(v.subspecs)])
	it('nests sub-specs under their spec, leaving out roots another root contains and closed sub-specs', () => {
		const views = specViews(findSpecs(tree.filter((i) => i.labels.includes('spec')), 'checkout'), source)
		expect(ids(views)).toEqual([
			['c', [['c.1', []], ['c.2', [['c.2.1', []]]]]],
			['r', []],
		])
		expect(views[0].requirements.map((r) => r.id)).toEqual(['c.9'])
		expect(views[0].subspecs[1].requirements.map((r) => r.id)).toEqual(['c.2.9'])
		expect(views[0].inherited).toEqual([])
	})
	it('gives a sub-spec the requirements in force of its ancestors, outermost first', () => {
		const [view] = specViews([source.get('c.2.1')], source)
		expect(view.inherited.map((a) => [a.spec.id, a.requirements.map((r) => r.id), a.nonGoals.map((r) => r.id)])).toEqual([
			['c', ['c.9'], ['c.8']],
			['c.2', ['c.2.9'], []],
		])
		expect(renderSpec(view)).toContain(
			'## Inherited\n\n- Requires sign-in (c.9; spec c)\n- Non-goal: No guest checkout (c.8; spec c)\n- Accepts cards (c.2.9; spec c.2)\n',
		)
	})
	it('renders sub-specs one heading level deeper', () => {
		const md = renderSpec(specViews([source.get('c')], source)[0])
		expect(md).toContain('## Sub-feature: Payment (c.2)\n\n### Requirements\n\n- Accepts cards (c.2.9)\n')
		expect(md).toContain('### Sub-feature: Saved cards (c.2.1)\n\n#### Requirements\n\n- Lists saved cards (c.2.1.9)\n')
		expect(md).not.toContain('Inherited')
	})
	it('fills inherited on nested views too, and passes no closed requirement down', () => {
		const [c] = specViews([source.get('c')], source)
		const saved = c.subspecs[1].subspecs[0]
		expect(saved.inherited.map((a) => [a.spec.id, a.requirements.map((r) => r.id)])).toEqual([
			['c', ['c.9']],
			['c.2', ['c.2.9']],
		])
	})
	it('shows an open spec under a closed one with an error and the fixes, and a spec under a non-spec issue with a warning', () => {
		const issues = [
			sp('a', 'A'),
			req('a.9', 'A rule'),
			{ ...sp('a.1', 'Closed B', 'a'), status: 'closed' },
			req('a.1.9', 'B rule'),
			sp('a.1.1', 'C', 'a.1'),
			req('a.1.1.9', 'C rule'),
			{ id: 'a.2', title: 'An epic', parent: 'a', status: 'open', labels: [] },
			sp('a.2.1', 'D', 'a.2'),
		]
		const src = sourceOf(issues)
		const views = specViews(findSpecs(issues.filter(isSpecIssue), 'checkout'), src)
		expect(views.map((v) => v.spec.id)).toEqual(['a', 'a.1.1', 'a.2.1'])
		const [, c, d] = views
		expect(c.inherited).toEqual([])
		expect(c.warnings).toEqual([])
		expect(c.errors).toEqual([
			'a.1.1 is open but its parent spec a.1 is closed, so it inherits nothing. Fix: reopen a.1 if it was closed by mistake ' +
				'(bd reopen a.1, then bd update a.1 --status pinned); close a.1.1 if the feature was retired (its requirements and ' +
				'sub-specs first, deepest first); or move a.1.1 under the spec that replaced a.1 (bd update a.1.1 --parent <spec>).',
		])
		const retired = [{ ...sp('w', 'W'), status: 'closed' }, { ...sp('w.1', 'V', 'w'), status: 'closed' }]
		expect(specViews([retired[1]], sourceOf(retired))[0].errors).toEqual([])
		expect(c.requirements.map((r) => r.id)).toEqual(['a.1.1.9'])
		expect(renderSpec(c)).toContain('> Error: a.1.1 is open but its parent spec a.1 is closed')
		expect(views[0].errors).toEqual([])
		expect(d.warnings).toEqual(["a.2.1's parent a.2 is not a spec: spec a above it is not inherited"])
		const underEpic = [{ id: 'e', title: 'Epic', parent: null, labels: [] }, sp('e.1', 'Top spec', 'e'), sp('x', 'Orphan', 'gone')]
		expect(specViews([underEpic[1], underEpic[2]], sourceOf(underEpic)).map((v) => v.warnings)).toEqual([[], []])
		expect(ancestors('a.1.1', src.get).chain).toEqual([])
	})
	it("carries an inherited requirement's warning to the view that inherits it", () => {
		const issues = [sp('a', 'A'), req('a.9', 'Open rule', { status: 'open' }), sp('a.1', 'B', 'a')]
		const [b] = specViews([issues[2]], sourceOf(issues))
		expect(b.warnings).toEqual(['inherited from a: a.9 is open, not pinned: pin it (bd update a.9 --status pinned) or close it'])
	})
	it('stops at the depth bound with a warning, and shows a root past it on its own', () => {
		const deep = Array.from({ length: MAX_DEPTH + 3 }, (_, i) => sp(`d${i}`, `Level ${i}`, i ? `d${i - 1}` : null))
		const src = sourceOf(deep)
		const views = specViews([deep[0], deep[MAX_DEPTH]], src)
		let v = views[0]
		for (let i = 1; i < MAX_DEPTH; i++) v = v.subspecs[0]
		expect(v.subspecs).toEqual([])
		expect(v.warnings).toEqual([`sub-spec d${MAX_DEPTH} not shown here: deeper than ${MAX_DEPTH} levels`])
		expect(views.map((x) => x.spec.id)).toEqual(['d0', `d${MAX_DEPTH}`])
		const up = ancestors(`d${MAX_DEPTH + 2}`, src.get)
		expect(up.chain.length).toBe(MAX_DEPTH)
		expect(up.warnings).toEqual([`d${MAX_DEPTH + 2} is nested deeper than ${MAX_DEPTH} specs: nothing above d2 is inherited`])
	})
	it('stops at a cycle with a warning', () => {
		const loop = [sp('a', 'A', 'b'), sp('b', 'B', 'a')]
		const [a] = specViews([loop[0]], sourceOf(loop))
		expect(a.subspecs[0].warnings).toEqual(['a is its own ancestor: not shown again'])
		expect(ancestors('a', sourceOf(loop).get)).toEqual({ chain: [loop[1]], warnings: ['a is its own ancestor: the chain stops there'], errors: [] })
	})
})

describe('renderSpec', () => {
	const view = specView(spec, children)
	it('renders requirements and non-goals, history only when asked', () => {
		const md = renderSpec(view)
		expect(md).toContain('# Spec: labels (s)\n\nLabels on issues.\n')
		expect(md).toContain('## Requirements\n\n- Labels can be set at create (s.1; from bd-w1)\n  With -l.\n  Repeatable.\n- Labels are case-insensitive (s.3; from bd-w2)\n')
		expect(md).toContain('## Non-goals\n\n- No label hierarchy (s.4)\n')
		expect(md).not.toContain('History')
		const full = renderSpec(view, { history: true })
		expect(full).toContain('- ~~Labels are case-sensitive~~ superseded by s.3 (s.2; from bd-w1)')
		expect(full).toContain('- ~~Labels have colours~~ removed: dropped in bd-w3[31m (s.5)')
	})
	it('says so when a section is empty', () => {
		expect(renderSpec(specView(spec, []))).toContain('## Requirements\n\nNone recorded.\n')
	})
})

describe('parseArgs', () => {
	it('takes one spec argument and the known options', () => {
		expect(parseArgs(['labels', '--root', 'd', '--history'])).toEqual({ arg: 'labels', root: 'd', history: true, json: false })
		expect(parseArgs(['--root=d', '--json', 'labels'])).toEqual({ arg: 'labels', root: 'd', history: false, json: true })
	})
	it('refuses a missing value, an unknown option or a second argument', () => {
		expect(() => parseArgs(['labels', '--root'])).toThrow(/--root needs a directory/)
		expect(() => parseArgs(['labels', '--hist'])).toThrow(/unexpected --hist/)
		expect(() => parseArgs(['-h'])).toThrow(/unexpected -h/)
		expect(() => parseArgs(['a', 'b'])).toThrow(/unexpected b/)
		expect(() => parseArgs([])).toThrow(/usage/)
	})
})

describe('spec', () => {
	let bin
	const script = fileURLToPath(new URL('./spec.mjs', import.meta.url))
	const call = (...args) => execFileSync('node', [script, ...args], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, stdio: ['ignore', 'pipe', 'pipe'] })
	beforeEach(() => {
		bin = mkdtempSync(join(tmpdir(), 'spec-'))
		// A bd over issues.json: list -l spec, query 'parent = "x" OR ...' (direct children), show (one id: an object).
		writeFileSync(join(bin, 'issues.json'), JSON.stringify([spec, ...children, ...tree]))
		writeFileSync(
			join(bin, 'bd'),
			[
				'#!/usr/bin/env node',
				`const all = JSON.parse(require('fs').readFileSync(${JSON.stringify(join(bin, 'issues.json'))}, 'utf8'))`,
				"const a = process.argv.slice(2).filter((x) => x !== '--json')",
				'const at = (f) => a[a.indexOf(f) + 1]',
				"const out = a.includes('show') ? a.slice(a.indexOf('show') + 1).map((id) => all.find((i) => i.id === id))",
				"  : a.includes('query') ? all.filter((i) => [...at('query').matchAll(/parent = \"([^\"]+)\"/g)].some((m) => i.parent === m[1]))",
				"  : all.filter((i) => (i.labels ?? []).includes(at('-l')))",
				"console.log(JSON.stringify(a.includes('show') && out.length === 1 ? out[0] : out))",
				'',
			].join('\n'),
		)
		chmodSync(join(bin, 'bd'), 0o755)
	})
	afterEach(() => rmSync(bin, { recursive: true, force: true }))

	it('prints the spec of an area as Markdown, or as JSON', () => {
		expect(call('labels')).toContain('- Labels are case-insensitive (s.3; from bd-w2)')
		const json = JSON.parse(call('labels', '--json'))
		expect(json.map((v) => v.spec.id)).toEqual(['s'])
		expect(json[0].history.length).toBe(2)
		expect(call('labels', '--history')).toContain('removed: dropped in bd-w3[31m (s.5)')
		expect(call('--root', bin, 'labels')).toContain('# Spec: labels (s)')
	})
	it('prints every spec of an area, sub-specs nested once, and a sub-spec with what it inherits', () => {
		const md = call('checkout')
		expect(md).toContain('# Checkout (c)')
		expect(md).toContain('### Sub-feature: Saved cards (c.2.1)')
		expect(md).toContain('# Receipts (r)')
		expect(md.match(/Saved cards/g).length).toBe(1)
		expect(md.match(/Requires sign-in/g).length).toBe(1)
		expect(call('c.2')).toContain('- Requires sign-in (c.9; spec c)')
	})
	it('fails with a message for an unknown spec', () => {
		expect(() => call('nope')).toThrow(/no spec nope/)
	})
})
