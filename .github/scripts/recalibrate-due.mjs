#!/usr/bin/env node
// Whether enough change runs have a confirmed score since the last recalibration, and starts the recalibrate
// playbook when they do. The last step of a change run calls it with --start.
//
//   node .github/scripts/recalibrate-due.mjs [--root <checkout>] [--every 10] [--start] [--actor <name>]
//
// A change run counts once its `score` metadata (a person's, or the judge's draft accepted with `by: judge`; not a bare
// `score_judge`) is set and it has no
// `recalibrated` metadata. --start runs `bd playbook run recalibrate` over the counted runs, then sets each one's
// `recalibrated` to the new run's id, so no run counts twice and a second call finds nothing due. Prints one JSON object:
// { due, count, every, runs, started }.
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { bdRunner } from './trace-run.mjs'

export const EVERY = 10

/** The change runs waiting for a recalibration, oldest first. */
export function pendingRuns(issues) {
  return issues
    .filter((i) => i.metadata?.playbook?.role === 'run' && i.metadata.playbook.name === 'change')
    .filter((i) => i.metadata.score != null && i.metadata.recalibrated == null)
    .toSorted((a, b) => (a.created_at ?? '').localeCompare(b.created_at ?? '') || a.id.localeCompare(b.id))
    .map((i) => i.id)
}

function main(argv) {
  const opt = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined)
  const root = opt('--root')
  const every = Number(opt('--every') ?? EVERY)
  if (!Number.isInteger(every) || every < 1) throw new Error('--every needs a positive whole number')
  const actor = opt('--actor')
  const bdArgs = (args) => [...(root ? ['-C', root] : []), ...args, ...(actor ? ['--actor', actor] : [])]
  const runs = pendingRuns(bdRunner(root)(['list', '--all', '-n', '0']))
  const due = runs.length >= every
  let started = null
  if (due && argv.includes('--start')) {
    started = execFileSync(
      'bd',
      bdArgs(['playbook', 'run', 'recalibrate', '--var', `count=${runs.length}`, '--var', `runs=${runs.join(',')}`, '-q']),
      { encoding: 'utf8' },
    ).trim()
    for (const id of runs) execFileSync('bd', bdArgs(['update', id, '--set-metadata', `recalibrated=${JSON.stringify(started)}`]), { stdio: ['ignore', 'ignore', 'pipe'] })
  }
  process.stdout.write(`${JSON.stringify({ due, count: runs.length, every, runs, started })}\n`)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2))
  } catch (e) {
    process.stderr.write(`recalibrate-due: ${(e.stderr?.toString().trim() || e.message).split('\n')[0]}\n`)
    process.exitCode = 1
  }
}
