#!/usr/bin/env node
// A feature's canonical requirements, from its spec issue in bd (AGENTS.md, Feature specs).
//
//   node .github/scripts/spec.mjs <spec id | area> [--root <checkout>] [--history] [--json]
//
// A spec is a pinned `feature` issue labelled `spec` and `area:<name>`; each requirement is a child labelled
// `requirement` (or `non-goal` for what the feature deliberately does not do). A pinned requirement is in force; a
// closed one was superseded (`bd supersede`) or removed (closed with its reason); any other status is a mistake, shown
// in force with a warning. A requirement's `related` edges name the issues or runs it came from. Prints the spec as
// Markdown (the requirements in force, the non-goals and, with --history, the closed ones), or with --json one object:
// { spec, requirements, nonGoals, history, warnings }.
import { fileURLToPath } from 'node:url'
import { bdRunner } from './trace-run.mjs'

// Issue text reaches terminals and agent context: drop control characters but newlines and tabs, and direction controls.
// eslint-disable-next-line no-control-regex
const clean = (s) => (s ?? '').replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')

/** The spec issue `arg` names, by id or by area, from the issues labelled `spec`. */
export function findSpec(specs, arg) {
  const byId = specs.find((s) => s.id === arg)
  if (byId) return byId
  const inArea = specs.filter((s) => (s.labels ?? []).includes(`area:${arg}`) && s.status !== 'closed')
  if (inArea.length === 1) return inArea[0]
  if (inArea.length > 1) throw new Error(`area ${arg} has ${inArea.length} specs: ${inArea.map((s) => s.id).join(', ')}`)
  throw new Error(`no spec ${arg}: name a spec issue's id or its area:<name> label`)
}

const edges = (issue, type) => (issue.dependencies ?? []).filter((d) => d.type === type).map((d) => d.id)

/** The spec view of a spec issue and its children (as bd show gives them, with their edges). */
export function specView(spec, children) {
  const reqs = children
    .filter((c) => (c.labels ?? []).some((l) => l === 'requirement' || l === 'non-goal'))
    .toSorted((a, b) => (a.created_at ?? '').localeCompare(b.created_at ?? '') || a.id.localeCompare(b.id))
  const item = (r) => ({ id: r.id, title: clean(r.title), description: clean(r.description), sources: edges(r, 'related') })
  const live = reqs.filter((r) => r.status !== 'closed')
  const nonGoal = (r) => (r.labels ?? []).includes('non-goal')
  return {
    spec: { id: spec.id, title: clean(spec.title), description: clean(spec.description) },
    requirements: live.filter((r) => !nonGoal(r)).map(item),
    nonGoals: live.filter(nonGoal).map(item),
    history: reqs
      .filter((r) => r.status === 'closed')
      .map((r) => {
        const by = edges(r, 'supersedes')[0] ?? null
        return { ...item(r), outcome: by ? 'superseded' : 'removed', by, reason: clean(r.close_reason), closedAt: r.closed_at ?? null }
      }),
    warnings: live
      .filter((r) => r.status !== 'pinned')
      .map((r) => `${r.id} is ${r.status}, not pinned: pin it (bd update ${r.id} --status pinned) or close it`),
  }
}

/** The spec view as Markdown. */
export function renderSpec(view, { history = false } = {}) {
  const lines = [`# ${view.spec.title} (${view.spec.id})`, '']
  if (view.spec.description) lines.push(view.spec.description, '')
  for (const w of view.warnings) lines.push(`> Warning: ${w}`, '')
  const entry = (r, head) => {
    lines.push(`- ${head} (${r.id}${r.sources.length ? `; from ${r.sources.join(', ')}` : ''})`)
    if (r.description) lines.push(...r.description.split('\n').map((l) => (l ? `  ${l}` : '')))
  }
  const section = (title, items, head) => {
    lines.push(`## ${title}`, '')
    if (items.length === 0) lines.push('None recorded.')
    for (const r of items) entry(r, head(r))
    lines.push('')
  }
  section('Requirements', view.requirements, (r) => r.title)
  section('Non-goals', view.nonGoals, (r) => r.title)
  if (history) {
    section('History', view.history, (r) =>
      r.outcome === 'superseded' ? `~~${r.title}~~ superseded by ${r.by}` : `~~${r.title}~~ removed: ${r.reason.replace(/^removed:\s*/i, '')}`,
    )
  }
  return `${lines.join('\n').trimEnd()}\n`
}

const USAGE = 'usage: spec.mjs <spec id | area> [--root <checkout>] [--history] [--json]'

/** The command line's spec argument and options; anything else is a usage error. */
export function parseArgs(argv) {
  const out = { arg: undefined, root: undefined, history: false, json: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--history') out.history = true
    else if (a === '--json') out.json = true
    else if (a === '--root' || a.startsWith('--root=')) {
      out.root = a === '--root' ? argv[++i] : a.slice('--root='.length)
      if (!out.root) throw new Error(`--root needs a directory; ${USAGE}`)
    } else if (a.startsWith('-') || out.arg !== undefined) throw new Error(`unexpected ${a}; ${USAGE}`)
    else out.arg = a
  }
  if (out.arg === undefined) throw new Error(USAGE)
  return out
}

function main(argv) {
  const { arg, root, history, json } = parseArgs(argv)
  const bd = bdRunner(root)
  const spec = findSpec(bd(['list', '--all', '-n', '0', '-l', 'spec']), arg)
  const ids = bd(['list', '--all', '-n', '0', '--parent', spec.id]).map((c) => c.id)
  const children = ids.length ? bd(['show', ...ids]) : []
  const view = specView(spec, children)
  process.stdout.write(json ? `${JSON.stringify(view, null, 2)}\n` : renderSpec(view, { history }))
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2))
  } catch (e) {
    process.stderr.write(`spec: ${(e.stderr?.toString().trim() || e.message).split('\n')[0]}\n`)
    process.exitCode = 1
  }
}
