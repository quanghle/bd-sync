#!/usr/bin/env node
// Run a full test suite while holding a machine-wide lock, so suites in different worktrees run one after another.
//
//   node .github/scripts/suite-lock.mjs [--run <id>] [--lock <dir>] [--max-wait <s>] [--poll <ms>] [--max-hold <s>] -- <command> [args...]
//
// The lock is a directory, <main checkout's git common dir>/bd-suite.lock (shared by every worktree of the repo;
// outside git, <os temp dir>/bd-suite.lock), taken with an atomic mkdir and holding owner.json: the owner's pid, run
// id, cwd, command, start time and a random token. While another process holds it, the wrapper waits (polling every
// --poll ms, default 2000, plus jitter) for at most --max-wait seconds (default 180); then it exits 75 (EX_TEMPFAIL)
// without running anything, and the caller runs the same command again. A lock is stale, and is reclaimed, when its
// owner's pid is dead, when it has been held longer than --max-hold seconds (default 5400), or when it has had no
// owner.json for 10 s; reclaiming goes through a second mkdir mutex, <lock>.reclaim, and re-checks the owner first.
// The command runs without a shell and the wrapper exits with its code (128 + n when signal n killed it, 127 when it
// was not found, 2 on a usage error). The lock is released when the command ends, on SIGINT/SIGTERM/SIGHUP (forwarded
// to the command) and on exit, and only while owner.json still carries this process's token.
// Use it for full suites only (`cargo test --workspace`); cargo fmt, cargo clippy and `cargo test -p <crate> [filter]`
// skip it, since cargo already serializes builds per target directory. The fallback lock in the os temp dir (outside
// any git checkout) is shared by every local user, so another user may create it; workflow worktrees always use the
// git common dir.
import { execFileSync, spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdirSync, readFileSync, renameSync, rmdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { constants, tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

export const LOCK_NAME = 'bd-suite.lock'
/** A lock dir without owner.json is stale once it is this old (ms): its owner died between mkdir and writing it. */
export const OWNERLESS_GRACE_MS = 10_000
/** A reclaim mutex this old (ms) was left by a waiter that died while reclaiming. */
export const RECLAIM_STALE_MS = 30_000
export const EX_USAGE = 2
export const EX_TEMPFAIL = 75
const DEFAULTS = { maxWait: 180, poll: 2000, maxHold: 5400 }

const say = (line) => process.stderr.write(`suite-lock: ${line}\n`)
const ownerText = (o) => `pid ${o?.pid ?? '?'}, run ${o?.run ?? '?'}`

/** The lock directory for the repository containing cwd: shared by all of its worktrees. */
export function lockPath(cwd) {
  try {
    const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
    if (common) return join(common, LOCK_NAME)
  } catch {
    // Not a git checkout: fall back to the temp dir.
  }
  return join(tmpdir(), LOCK_NAME)
}

/** The lock's owner.json, parsed, or null when it is missing or unreadable. */
export function readOwner(lock) {
  try {
    return JSON.parse(readFileSync(join(lock, 'owner.json'), 'utf8'))
  } catch {
    return null
  }
}

/** Whether a process with this pid exists (EPERM: it exists but belongs to someone else). */
export function alive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return e.code === 'EPERM'
  }
}

/** Whether a held lock may be reclaimed: ownerless past the grace, owner dead, or held past maxHoldMs. */
export function isStale(owner, { now = Date.now(), mtimeMs, maxHoldMs = DEFAULTS.maxHold * 1000, alive: isAlive = alive } = {}) {
  if (!owner) return now - mtimeMs > OWNERLESS_GRACE_MS
  if (!isAlive(owner.pid)) return true
  if (now - Date.parse(owner.started) > maxHoldMs) return true
  return false
}

const mtimeOf = (path) => {
  try {
    return statSync(path).mtimeMs
  } catch {
    return null
  }
}

/** Remove the stale lock if it still has the owner we judged stale. True when the lock is gone. */
function reclaim(lock, seen, maxHoldMs) {
  const mutex = `${lock}.reclaim`
  try {
    mkdirSync(mutex)
  } catch (e) {
    if (e.code !== 'EEXIST') throw e
    const m = mtimeOf(mutex)
    if (m !== null && Date.now() - m > RECLAIM_STALE_MS) rmSync(mutex, { recursive: true, force: true })
    return false
  }
  try {
    const mtimeMs = mtimeOf(lock)
    if (mtimeMs === null) return true
    const owner = readOwner(lock)
    if ((owner?.token ?? null) !== (seen?.token ?? null) || !isStale(owner, { mtimeMs, maxHoldMs })) return false
    rmSync(lock, { recursive: true, force: true })
    say(`reclaimed a stale lock from pid ${owner?.pid ?? '?'} (run ${owner?.run ?? '?'})`)
    return true
  } finally {
    rmdirSync(mutex)
  }
}

/**
 * Take the lock, waiting while a live owner holds it. Returns { token } once taken, or { busy: owner } when
 * maxWaitMs ran out first.
 */
export async function acquire({ lock, run = null, command = '', maxWaitMs = DEFAULTS.maxWait * 1000, pollMs = DEFAULTS.poll, maxHoldMs = DEFAULTS.maxHold * 1000 }) {
  const deadline = Date.now() + maxWaitMs
  let announced
  for (;;) {
    try {
      mkdirSync(lock)
      const token = randomBytes(8).toString('hex')
      const owner = { pid: process.pid, run, cwd: process.cwd(), command, started: new Date().toISOString(), token }
      const tmp = join(lock, 'owner.json.tmp')
      writeFileSync(tmp, `${JSON.stringify(owner, null, 2)}\n`)
      renameSync(tmp, join(lock, 'owner.json'))
      return { token }
    } catch (e) {
      if (e.code !== 'EEXIST') throw e
    }
    const owner = readOwner(lock)
    const mtimeMs = mtimeOf(lock)
    if (mtimeMs === null) continue // released between our mkdir and stat: try again at once
    if (isStale(owner, { mtimeMs, maxHoldMs }) && reclaim(lock, owner, maxHoldMs)) continue
    const left = deadline - Date.now()
    if (left <= 0) return { busy: owner }
    const key = owner?.token ?? ''
    if (announced !== key) {
      announced = key
      say(`waiting for ${lock} (held by ${ownerText(owner)} since ${owner?.started ?? '?'})`)
    }
    await sleep(Math.min(left, pollMs + Math.floor(Math.random() * Math.min(pollMs, 500))))
  }
}

/** Remove the lock, only while it is still ours. */
export function release(lock, token) {
  if (token && readOwner(lock)?.token === token) rmSync(lock, { recursive: true, force: true })
}

export function parseArgs(argv) {
  const sep = argv.indexOf('--')
  if (sep < 0 || sep === argv.length - 1) return null
  const opts = { run: null, lock: null, ...DEFAULTS }
  const names = { '--run': 'run', '--lock': 'lock', '--max-wait': 'maxWait', '--poll': 'poll', '--max-hold': 'maxHold' }
  const head = argv.slice(0, sep)
  for (let i = 0; i < head.length; i += 2) {
    const key = names[head[i]]
    const value = head[i + 1]
    if (!key || value === undefined) return null
    if (key === 'run' || key === 'lock') opts[key] = value
    else {
      const n = Number(value)
      if (!Number.isFinite(n) || n < 0) return null
      opts[key] = n
    }
  }
  return { ...opts, command: argv.slice(sep + 1) }
}

const USAGE = 'usage: node .github/scripts/suite-lock.mjs [--run <id>] [--lock <dir>] [--max-wait <s>] [--poll <ms>] [--max-hold <s>] -- <command> [args...]'

/** Run the command under the lock and resolve to the exit code for the wrapper. */
export async function main(argv) {
  const opts = parseArgs(argv)
  if (!opts) {
    process.stderr.write(`${USAGE}\n`)
    return EX_USAGE
  }
  const lock = opts.lock ?? lockPath(process.cwd())
  const [cmd, ...args] = opts.command
  let token = null
  let child = null
  const backstop = () => release(lock, token)
  process.on('exit', backstop)
  const handlers = ['SIGINT', 'SIGTERM', 'SIGHUP'].map((sig) => {
    let forwarded = false
    const handler = () => {
      // Pass the first signal on and keep the lock until the child has exited (its 'close' resolves main,
      // whose finally releases), so no other suite starts while this one is still running. A second
      // signal, or one before the child started, releases and exits at once.
      if (!forwarded && child && child.exitCode === null && child.signalCode === null) {
        forwarded = true
        child.kill(sig)
        return
      }
      release(lock, token)
      process.exit(128 + constants.signals[sig])
    }
    process.on(sig, handler)
    return [sig, handler]
  })
  try {
    const got = await acquire({
      lock,
      run: opts.run,
      command: opts.command.join(' '),
      maxWaitMs: opts.maxWait * 1000,
      pollMs: opts.poll,
      maxHoldMs: opts.maxHold * 1000,
    })
    if (got.busy !== undefined) {
      say(`still busy after ${opts.maxWait}s (held by ${ownerText(got.busy)}); nothing ran, run the same command again`)
      return EX_TEMPFAIL
    }
    token = got.token
    return await new Promise((resolve) => {
      child = spawn(cmd, args, { stdio: 'inherit' })
      child.on('error', (e) => {
        say(`could not start ${cmd}: ${e.message}`)
        resolve(e.code === 'ENOENT' ? 127 : 126)
      })
      child.on('close', (code, signal) => resolve(code ?? 128 + (constants.signals[signal] ?? 0)))
    })
  } finally {
    release(lock, token)
    token = null
    for (const [sig, handler] of handlers) process.off(sig, handler)
    process.off('exit', backstop)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`suite-lock: ${e.message}\n`)
      process.exit(1)
    },
  )
}
