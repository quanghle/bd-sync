import { execFileSync, spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import { alive, isStale, LOCK_NAME, lockPath, OWNERLESS_GRACE_MS, parseArgs } from './suite-lock.mjs'

// Every locking case uses a lock under its own temp dir, never lockPath(): this spec can run inside a gate that holds the
// real lock.
const WRAPPER = fileURLToPath(new URL('./suite-lock.mjs', import.meta.url))
const NODE = process.execPath

let dir
let lock
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), 'suite-lock-'))
	lock = join(dir, 'lock')
})
afterEach(() => {
	rmSync(dir, { recursive: true, force: true })
})

/** Run the wrapper on the temp lock; resolves with its exit code, signal and stderr. */
function wrap(args, command, env = {}) {
	const child = spawn(NODE, [WRAPPER, '--lock', lock, '--poll', '50', ...args, '--', ...command], {
		env: { ...process.env, ...env },
		stdio: ['ignore', 'ignore', 'pipe'],
	})
	let stderr = ''
	child.stderr.on('data', (d) => (stderr += d))
	const done = new Promise((resolve) => child.on('close', (code, signal) => resolve({ code, signal, stderr })))
	return { child, done }
}

/** Poll every 20 ms, for up to `ms` (10 s by default), until `file` exists. */
async function waitForFile(file, ms = 10_000) {
	const until = Date.now() + ms
	while (!existsSync(file) && Date.now() < until) await new Promise((r) => setTimeout(r, 20))
}

/** A node child that appends 'start <id>', waits about 300 ms, then appends 'end <id>' to EV_FILE. */
const holder = [NODE, '-e', "const fs=require('fs');const f=process.env.EV_FILE,id=process.env.EV_ID;fs.appendFileSync(f,'start '+id+'\\n');setTimeout(()=>fs.appendFileSync(f,'end '+id+'\\n'),300)"]
const touch = (file) => [NODE, '-e', `require('fs').writeFileSync(${JSON.stringify(file)}, 'ran')`]
const writeOwner = (owner) => {
	mkdirSync(lock)
	writeFileSync(join(lock, 'owner.json'), JSON.stringify(owner))
}

describe('suite-lock', () => {
	it('runs two holders started together one after the other and removes the lock', { timeout: 20_000 }, async () => {
		const events = join(dir, 'events')
		const x = wrap(['--run', 'run-x'], holder, { EV_FILE: events, EV_ID: 'X' })
		const y = wrap(['--run', 'run-y'], holder, { EV_FILE: events, EV_ID: 'Y' })
		const [rx, ry] = await Promise.all([x.done, y.done])
		expect([rx.code, ry.code]).toEqual([0, 0])
		const lines = readFileSync(events, 'utf8').trim().split('\n')
		const first = lines[0].slice('start '.length)
		const second = first === 'X' ? 'Y' : 'X'
		expect(lines).toEqual([`start ${first}`, `end ${first}`, `start ${second}`, `end ${second}`])
		expect((second === 'X' ? rx : ry).stderr).toContain('waiting')
		expect((first === 'X' ? rx : ry).stderr).not.toContain('waiting')
		for (const r of [rx, ry]) expect(r.stderr).not.toMatch(/ RUN /)
		expect(existsSync(lock)).toBe(false)
		expect(existsSync(`${lock}.reclaim`)).toBe(false)
	})

	it('reclaims a lock whose owner pid is dead', { timeout: 20_000 }, async () => {
		const dead = spawnSync(NODE, ['-e', '']).pid
		expect(alive(dead)).toBe(false)
		writeOwner({ pid: dead, run: 'old', started: new Date().toISOString(), token: 'dead' })
		const marker = join(dir, 'ran')
		const r = await wrap(['--run', 'new'], touch(marker)).done
		expect(r.code).toBe(0)
		expect(existsSync(marker)).toBe(true)
		expect(r.stderr).toContain(`reclaimed a stale lock from pid ${dead} (run old)`)
		expect(existsSync(lock)).toBe(false)
	})

	it('waits for a live owner and exits 75 without running the command when --max-wait runs out', { timeout: 20_000 }, async () => {
		writeOwner({ pid: process.pid, run: 'live', started: new Date().toISOString(), token: 'live' })
		const before = readFileSync(join(lock, 'owner.json'))
		const marker = join(dir, 'ran')
		const r = await wrap(['--max-wait', '1'], touch(marker)).done
		expect(r.code).toBe(75)
		expect(existsSync(marker)).toBe(false)
		expect(readFileSync(join(lock, 'owner.json')).equals(before)).toBe(true)
		expect(r.stderr).toContain(`waiting for ${lock} (held by pid ${process.pid}, run live since `)
		expect(r.stderr).toContain(`still busy after 1s (held by pid ${process.pid}, run live); nothing ran, run the same command again`)
	})

	it("passes the command's exit code through and releases the lock after a failure", { timeout: 20_000 }, async () => {
		const r = await wrap([], [NODE, '-e', 'process.exit(3)']).done
		expect(r.code).toBe(3)
		expect(existsSync(lock)).toBe(false)
	})

	it('exits 127 when the command does not exist, and 2 on a usage error', { timeout: 20_000 }, async () => {
		const missing = await wrap([], [join(dir, 'no-such-command')]).done
		expect(missing.code).toBe(127)
		expect(existsSync(lock)).toBe(false)
		const usage = spawnSync(NODE, [WRAPPER, '--lock', lock, 'cargo', 'test'], { encoding: 'utf8' })
		expect(usage.status).toBe(2)
		expect(usage.stderr).toContain('usage:')
		const empty = spawnSync(NODE, [WRAPPER, '--lock', lock, '--'], { encoding: 'utf8' })
		expect(empty.status).toBe(2)
		expect(empty.stderr).toContain('usage:')
		expect(existsSync(lock)).toBe(false)
	})

	it('releases the lock on SIGTERM', { skip: process.platform === 'win32' && 'no POSIX signals', timeout: 20_000 }, async () => {
		const { child, done } = wrap([], [NODE, '-e', 'setTimeout(() => {}, 10000)'])
		await waitForFile(join(lock, 'owner.json'))
		expect(existsSync(join(lock, 'owner.json'))).toBe(true)
		child.kill('SIGTERM')
		const r = await done
		expect(r.code).toBe(143)
		expect(existsSync(lock)).toBe(false)
	})

	it('keeps the lock on SIGTERM until the command has exited', { skip: process.platform === 'win32' && 'no POSIX signals', timeout: 20_000 }, async () => {
		const ended = join(dir, 'ended')
		const ready = join(dir, 'ready')
		const stopping = join(dir, 'stopping')
		const go = join(dir, 'go')
		// The command winds down after SIGTERM, like a suite closing its browsers. It writes `ready` only once its
		// SIGTERM handler exists, so the signal never arrives before the handler. On SIGTERM it writes `stopping` and
		// blocks until the test writes `go`, so the mid-shutdown state is held by construction, not by timer margins.
		// Without `go` it gives up after 10 s and exits 1 without writing `ended`, so a failed test leaves no child behind.
		const [END, RDY, STOP, GO] = [ended, ready, stopping, go].map((f) => JSON.stringify(f))
		const slow = [
			NODE,
			'-e',
			`const fs=require('fs');process.on('SIGTERM',()=>{fs.writeFileSync(${STOP},'x');const cap=Date.now()+10000;const t=setInterval(()=>{if(fs.existsSync(${GO})){clearInterval(t);fs.writeFileSync(${END},'x');process.exit(0)}else if(Date.now()>cap)process.exit(1)},20)});fs.writeFileSync(${RDY},'x');setTimeout(()=>{},10000)`,
		]
		const { child, done } = wrap([], slow)
		await waitForFile(ready)
		expect(existsSync(ready)).toBe(true)
		expect(existsSync(join(lock, 'owner.json'))).toBe(true)
		child.kill('SIGTERM')
		await waitForFile(stopping)
		expect(existsSync(stopping)).toBe(true)
		expect(existsSync(ended)).toBe(false)
		expect(existsSync(lock)).toBe(true)
		writeFileSync(go, 'x')
		const r = await done
		expect(existsSync(ended)).toBe(true)
		expect(r.code).toBe(0)
		expect(existsSync(lock)).toBe(false)
	})

	it('reclaims a lock held longer than --max-hold even when its owner is alive', { timeout: 20_000 }, async () => {
		writeOwner({ pid: process.pid, run: 'long', started: new Date(Date.now() - 3600_000).toISOString(), token: 'long' })
		const marker = join(dir, 'ran')
		const r = await wrap(['--max-hold', '60'], touch(marker)).done
		expect(r.code).toBe(0)
		expect(existsSync(marker)).toBe(true)
		expect(r.stderr).toContain('reclaimed a stale lock from pid')
		expect(existsSync(lock)).toBe(false)
	})

	it("puts the lock in the repository's git common dir, shared by every worktree", { timeout: 20_000 }, () => {
		const git = (args, cwd = dir) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
		git(['-c', 'init.defaultBranch=main', 'init', '-q', 'repo'])
		git(['-C', 'repo', '-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'init'])
		git(['-C', 'repo', 'worktree', 'add', '-q', '../wt', '-b', 'wt'])
		const shared = lockPath(join(dir, 'repo'))
		expect(lockPath(join(dir, 'wt'))).toBe(shared)
		expect(shared.endsWith(join('.git', 'bd-suite.lock'))).toBe(true)
		const common = git(['rev-parse', '--path-format=absolute', '--git-common-dir'], process.cwd()).trim()
		expect(lockPath(process.cwd())).toBe(join(common, 'bd-suite.lock'))
	})

	it('falls back to the os temp dir outside a git checkout', () => {
		expect(lockPath(dir)).toBe(join(tmpdir(), 'bd-suite.lock'))
	})
})

const live = () => true
const dead = () => false

describe('isStale', () => {
	const now = Date.parse('2026-10-19T12:00:00Z')
	const owner = { pid: 1234, started: '2026-10-19T11:00:00Z' }
	it('gives an ownerless lock a grace period', () => {
		expect(isStale(null, { now, mtimeMs: now - OWNERLESS_GRACE_MS + 1, alive: live })).toBe(false)
		expect(isStale(null, { now, mtimeMs: now - OWNERLESS_GRACE_MS - 1, alive: live })).toBe(true)
	})
	it('is stale when the owner is dead or has held it past maxHoldMs', () => {
		expect(isStale(owner, { now, mtimeMs: now, maxHoldMs: 7200_000, alive: dead })).toBe(true)
		expect(isStale(owner, { now, mtimeMs: now, maxHoldMs: 7200_000, alive: live })).toBe(false)
		expect(isStale(owner, { now, mtimeMs: now, maxHoldMs: 1800_000, alive: live })).toBe(true)
	})
	it('treats EPERM as alive and a missing or invalid pid as dead', () => {
		expect(alive(process.pid)).toBe(true)
		if (process.platform !== 'win32') expect(alive(1)).toBe(true) // launchd or init: EPERM for a normal user
		expect(alive(undefined)).toBe(false)
		expect(alive(0)).toBe(false)
	})
})

describe('parseArgs', () => {
	it('reads options before -- and the command after it', () => {
		expect(parseArgs(['--run', 'bd-x.1', '--max-wait', '5', '--', 'cargo', 'test', '--workspace'])).toEqual({
			run: 'bd-x.1',
			lock: null,
			maxWait: 5,
			poll: 2000,
			maxHold: 5400,
			command: ['cargo', 'test', '--workspace'],
		})
		expect(parseArgs(['cargo', 'test'])).toBeNull()
		expect(parseArgs(['--run', 'x', '--'])).toBeNull()
		expect(parseArgs(['--bogus', '1', '--', 'cargo'])).toBeNull()
		expect(parseArgs(['--poll', 'soon', '--', 'cargo'])).toBeNull()
		expect(parseArgs(['--max-wait', '-1', '--', 'cargo'])).toBeNull()
		expect(parseArgs(['--run', '--', 'cargo'])).toBeNull()
	})
	it('defaults every option', () => {
		expect(parseArgs(['--', 'cargo', 'test', '--workspace', '--locked'])).toEqual({
			run: null,
			lock: null,
			maxWait: 180,
			poll: 2000,
			maxHold: 5400,
			command: ['cargo', 'test', '--workspace', '--locked'],
		})
		expect(LOCK_NAME).toBe('bd-suite.lock')
	})
})
