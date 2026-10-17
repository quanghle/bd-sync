import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import { execFileSync } from 'node:child_process'
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { findSpec, parseArgs, renderSpec, specView } from './spec.mjs'

const spec = { id: 's', title: 'Spec: labels', description: 'Labels on issues.', status: 'pinned', labels: ['spec', 'area:labels'] }
const req = (id, title, { status = 'pinned', labels = [], deps = [], created_at = `2026-10-15T00:00:0${id.at(-1)}Z`, ...rest } = {}) => ({
	id,
	title,
	status,
	created_at,
	labels: ['requirement', ...labels],
	dependencies: deps.map(([type, to]) => ({ id: to, type })),
	...rest,
})
const children = [
	req('s.3', 'Labels are case-insensitive', { deps: [['related', 'bd-w2']] }),
	req('s.1', 'Labels can be set at create', { deps: [['related', 'bd-w1']], description: 'With -l.\nRepeatable.' }),
	req('s.2', 'Labels are case-sensitive', { status: 'closed', deps: [['supersedes', 's.3'], ['related', 'bd-w1']], close_reason: 'superseded by s.3' }),
	{ ...req('s.4', 'No label hierarchy'), labels: ['non-goal'] },
	req('s.7', 'Labels show in brief output\u202e', { status: 'open' }),
	req('s.5', 'Labels have colours', { status: 'closed', close_reason: 'Removed: dropped in bd-w3\u001b[31m' }),
	{ id: 's.6', title: 'Not a requirement', status: 'closed', labels: [] },
]

describe('findSpec', () => {
	const other = { ...spec, id: 'o', labels: ['spec', 'area:query'] }
	it('finds a spec by id or by area', () => {
		expect(findSpec([spec, other], 'o')).toBe(other)
		expect(findSpec([spec, other], 'labels')).toBe(spec)
	})
	it('refuses an unknown or ambiguous area, ignoring closed specs', () => {
		expect(() => findSpec([spec], 'nope')).toThrow(/no spec nope/)
		expect(() => findSpec([spec, { ...spec, id: 't' }], 'labels')).toThrow(/2 specs: s, t/)
		expect(findSpec([spec, { ...spec, id: 't', status: 'closed' }], 'labels')).toBe(spec)
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
		writeFileSync(join(bin, 'specs.json'), JSON.stringify([spec]))
		writeFileSync(join(bin, 'kids.json'), JSON.stringify(children.map(({ id }) => ({ id }))))
		writeFileSync(join(bin, 'show.json'), JSON.stringify(children))
		writeFileSync(
			join(bin, 'bd'),
			['#!/bin/sh', 'case "$*" in', `  *"-l spec"*) cat ${join(bin, 'specs.json')};;`, `  *"--parent s"*) cat ${join(bin, 'kids.json')};;`, `  *"show "*) cat ${join(bin, 'show.json')};;`, 'esac', ''].join('\n'),
		)
		chmodSync(join(bin, 'bd'), 0o755)
	})
	afterEach(() => rmSync(bin, { recursive: true, force: true }))

	it('prints the spec of an area as Markdown, or as JSON', () => {
		expect(call('labels')).toContain('- Labels are case-insensitive (s.3; from bd-w2)')
		const json = JSON.parse(call('labels', '--json'))
		expect(json.spec.id).toBe('s')
		expect(json.history.length).toBe(2)
		expect(call('labels', '--history')).toContain('removed: dropped in bd-w3[31m (s.5)')
		expect(call('--root', bin, 'labels')).toContain('# Spec: labels (s)')
	})
	it('fails with a message for an unknown spec', () => {
		expect(() => call('nope')).toThrow(/no spec nope/)
	})
})
