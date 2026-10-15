import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import { execFileSync } from 'node:child_process'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { pendingRuns } from './recalibrate-due.mjs'

const run = (id, metadata = {}, name = 'change', created_at = '2026-10-15T00:00:00Z') => ({
	id,
	created_at,
	metadata: { playbook: { name, role: 'run' }, ...metadata },
})
const score = { overall: 4 }

describe('pendingRuns', () => {
	it('counts change runs with a confirmed score and no recalibration, oldest first', () => {
		const issues = [
			run('b', { score }, 'change', '2026-10-15T02:00:00Z'),
			run('a', { score }, 'change', '2026-10-15T01:00:00Z'),
			run('judged', { score_judge: score }),
			run('done', { score, recalibrated: 'r1' }),
			run('other', { score }, 'score'),
			{ id: 'plain', created_at: '2026-10-15T00:00:00Z' },
		]
		expect(pendingRuns(issues)).toEqual(['a', 'b'])
	})
})

describe('recalibrate-due', () => {
	let bin
	const script = fileURLToPath(new URL('./recalibrate-due.mjs', import.meta.url))
	const call = (...args) => {
		try {
			return JSON.parse(execFileSync('node', [script, ...args], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, stdio: ['ignore', 'pipe', 'pipe'] }))
		} catch (e) {
			throw new Error(`exit ${e.status}: ${e.stderr}`, { cause: e })
		}
	}
	const calls = () => readFileSync(join(bin, 'calls'), 'utf8')
	beforeEach(() => {
		bin = mkdtempSync(join(tmpdir(), 'recal-'))
		writeFileSync(join(bin, 'list.json'), JSON.stringify([run('r1', { score }), run('r2', { score }), run('r3', { score }, 'change', '2026-10-15T03:00:00Z')]))
		writeFileSync(
			join(bin, 'bd'),
			[
				'#!/bin/sh',
				`echo "$@" >> ${join(bin, 'calls')}`,
				'case "$*" in',
				`  "list "*|*" list "*) cat ${join(bin, 'list.json')};;`,
				'  *"playbook run"*) echo bd-new;;',
				'esac',
				'',
			].join('\n'),
		)
		chmodSync(join(bin, 'bd'), 0o755)
	})
	afterEach(() => rmSync(bin, { recursive: true, force: true }))

	it('says not due below the count and starts nothing', () => {
		expect(call('--every', '4', '--start')).toEqual({ due: false, count: 3, every: 4, runs: ['r1', 'r2', 'r3'], started: null })
		expect(calls()).not.toContain('playbook run')
		expect(calls()).not.toContain('update ')
	})

	it('only reports when due without --start', () => {
		expect(call('--every', '3').due).toBe(true)
		expect(calls()).not.toContain('playbook run')
	})

	it('starts the playbook over the counted runs and marks each one', () => {
		const out = call('--every', '3', '--start', '--actor', 'me')
		expect(out).toEqual({ due: true, count: 3, every: 3, runs: ['r1', 'r2', 'r3'], started: 'bd-new' })
		expect(calls()).toContain('playbook run recalibrate --var count=3 --var runs=r1,r2,r3 -q --actor me')
		for (const id of ['r1', 'r2', 'r3']) expect(calls()).toContain(`update ${id} --set-metadata recalibrated="bd-new" --actor me`)
	})

	it('rejects a bad --every', () => {
		expect(() => call('--every', '0')).toThrow()
	})
})
