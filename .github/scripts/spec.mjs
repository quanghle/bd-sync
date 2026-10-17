#!/usr/bin/env node
// A feature's canonical requirements, from its spec issue in bd (AGENTS.md, Feature specs).
//
//   node .github/scripts/spec.mjs <spec id | area> [--root <checkout>] [--history] [--json]
//
// A spec is a pinned `feature` issue labelled `spec` and `area:<name>`; each requirement is a child labelled
// `requirement` (or `non-goal` for what the feature deliberately does not do). A pinned requirement is in force; a
// closed one was superseded (`bd supersede`) or removed (closed with its reason); any other status is a mistake, shown
// in force with a warning. A requirement's `related` edges name the issues or runs it came from. A spec may be the
// child of another spec (a sub-feature): its parent's requirements apply to it too. An area may hold several specs.
// Only an open spec passes its requirements down. An open spec under a closed one is an error (bd refuses to close a
// spec with open children unless forced): it is still printed, inheriting nothing, with the ways to fix it. An issue
// that is not a spec between two specs ends the chain with a warning. Prints each spec named (by id, or every open
// spec of the area but those shown inside another one) as Markdown: the requirements in force, the non-goals, the
// requirements inherited from the specs above it (for the specs printed at the top; below them, the specs above are on
// the page), its sub-specs nested beneath it and, with --history, the closed requirements at every level. --json
// prints an array of views: { spec, requirements, nonGoals, history, errors, warnings, inherited, subspecs }, every nested
// view with its own full `inherited`.
import { fileURLToPath } from 'node:url'
import { bdRunner } from './trace-run.mjs'

// Issue text reaches terminals and agent context: drop control characters but newlines and tabs, and direction controls.
// eslint-disable-next-line no-control-regex
const clean = (s) => (s ?? '').replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')

/** Nesting deeper than this is not walked (a warning says where it stopped). */
export const MAX_DEPTH = 8

export const isSpec = (issue) => (issue?.labels ?? []).includes('spec')

/** The spec issues `arg` names, by id or by area, from the issues labelled `spec`. */
export function findSpecs(specs, arg) {
  const byId = specs.find((s) => s.id === arg)
  if (byId) return [byId]
  const inArea = specs.filter((s) => (s.labels ?? []).includes(`area:${arg}`) && s.status !== 'closed')
  if (inArea.length) return inArea.toSorted((a, b) => a.id.localeCompare(b.id))
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

/**
 * A spec's chain of ancestor specs, nearest first, and why it stopped where it did. Only an open spec continues the
 * chain: a closed spec ends it with an error (an open spec under a closed one is always a mistake), an issue that is
 * not a spec, MAX_DEPTH or a cycle with a warning.
 */
export function ancestors(id, get) {
  const chain = []
  const warnings = []
  const errors = []
  const seen = new Set([id])
  for (let at = id, parent = get(id)?.parent; parent; at = parent, parent = get(parent)?.parent) {
    const issue = get(parent)
    if (!isSpec(issue)) {
      // Worth a warning only when it cuts a spec off: some spec above it would have passed requirements down.
      let above = issue?.parent
      for (let n = 0; above && n < MAX_DEPTH && !isSpec(get(above)); n++) above = get(above)?.parent
      if (above && isSpec(get(above))) warnings.push(`${at}'s parent ${parent} is not a spec: spec ${above} above it is not inherited`)
      break
    }
    if (issue.status === 'closed') {
      // Only an open spec under a closed one is a mistake: a closed spec under a closed one was retired with it.
      if (get(at)?.status !== 'closed') {
        errors.push(
          `${at} is open but its parent spec ${parent} is closed, so it inherits nothing. Fix: reopen ${parent} if it was ` +
            `closed by mistake (bd reopen ${parent}, then bd update ${parent} --status pinned); close ${at} if the feature ` +
            `was retired (its requirements and sub-specs first, deepest first); or move ${at} under the spec that ` +
            `replaced ${parent} (bd update ${at} --parent <spec>).`,
        )
      }
      break
    }
    if (seen.has(parent)) {
      warnings.push(`${parent} is its own ancestor: the chain stops there`)
      break
    }
    if (chain.length >= MAX_DEPTH) {
      warnings.push(`${id} is nested deeper than ${MAX_DEPTH} specs: nothing above ${at} is inherited`)
      break
    }
    seen.add(parent)
    chain.push(issue)
  }
  return { chain, warnings, errors }
}

/**
 * The views of the spec issues `roots`, from a source of issues: get(id) an issue as bd show gives it (with its parent
 * and edges), kids(id) its children's ids, and optionally prefetch(ids) to load several specs' children at once. Each
 * view nests its open sub-specs (to MAX_DEPTH) and lists in `inherited` the requirements in force of the specs above
 * it, outermost first. A root shown inside an earlier root's tree is left out; roots are taken shallowest first.
 */
export function specViews(roots, { get, kids, prefetch = () => {} }) {
  const children = (id) => kids(id).map(get).filter(Boolean)
  const own = (issue) => {
    const view = specView(issue, children(issue.id))
    return { spec: view.spec, requirements: view.requirements, nonGoals: view.nonGoals, warnings: view.warnings }
  }
  const shown = new Set()
  const tree = (issue, depth, seen, inherited) => {
    shown.add(issue.id)
    const below = children(issue.id)
    const view = specView(issue, below)
    view.errors = []
    view.inherited = inherited
    view.subspecs = []
    const subs = below.filter((c) => isSpec(c) && c.status !== 'closed')
    prefetch(subs.map((c) => c.id))
    const passed = [...inherited, { spec: view.spec, requirements: view.requirements, nonGoals: view.nonGoals }]
    for (const c of subs) {
      if (seen.has(c.id)) view.warnings.push(`${c.id} is its own ancestor: not shown again`)
      else if (depth >= MAX_DEPTH) view.warnings.push(`sub-spec ${c.id} not shown here: deeper than ${MAX_DEPTH} levels`)
      else view.subspecs.push(tree(c, depth + 1, new Set([...seen, c.id]), passed))
    }
    return view
  }
  prefetch(roots.map((r) => r.id))
  const placed = roots.map((r) => ({ issue: get(r.id) ?? r, up: ancestors(r.id, get) }))
  const views = []
  for (const { issue, up } of placed.toSorted((a, b) => a.up.chain.length - b.up.chain.length)) {
    if (shown.has(issue.id)) continue
    const inherited = up.chain.toReversed().map(own)
    const view = tree(issue, 1, new Set([issue.id]), inherited.map(({ warnings, ...a }) => a))
    view.errors.push(...up.errors)
    view.warnings.unshift(...up.warnings, ...inherited.flatMap((a) => a.warnings.map((w) => `inherited from ${a.spec.id}: ${w}`)))
    views.push(view)
  }
  // Keep the order roots were named in (by id), whatever order they were placed in.
  const order = new Map(roots.map((r, i) => [r.id, i]))
  return views.toSorted((a, b) => order.get(a.spec.id) - order.get(b.spec.id))
}

/** A spec view as Markdown, its headings starting at `level`; sub-specs one level deeper. */
export function renderSpec(view, { history = false, level = 1 } = {}) {
  const h = (n) => '#'.repeat(Math.min(n, 6))
  const lines = [`${h(level)} ${level > 1 ? 'Sub-feature: ' : ''}${view.spec.title} (${view.spec.id})`, '']
  if (view.spec.description) lines.push(view.spec.description, '')
  for (const e of view.errors ?? []) lines.push(`> Error: ${e}`, '')
  for (const w of view.warnings) lines.push(`> Warning: ${w}`, '')
  const entry = (r, head, from) => {
    const refs = [r.id, ...(from ? [`spec ${from}`] : []), ...(r.sources.length ? [`from ${r.sources.join(', ')}`] : [])]
    lines.push(`- ${head} (${refs.join('; ')})`)
    if (r.description) lines.push(...r.description.split('\n').map((l) => (l ? `  ${l}` : '')))
  }
  const section = (title, items, head = (r) => r.title, from = () => null) => {
    lines.push(`${h(level + 1)} ${title}`, '')
    if (items.length === 0) lines.push('None recorded.')
    for (const r of items) entry(r, head(r), from(r))
    lines.push('')
  }
  section('Requirements', view.requirements)
  section('Non-goals', view.nonGoals)
  // A nested view's inherited requirements are the views above it on the page: listed only at the top.
  const inherited = (level === 1 ? (view.inherited ?? []) : []).flatMap((a) => [
    ...a.requirements.map((r) => ({ ...r, spec: a.spec.id })),
    ...a.nonGoals.map((r) => ({ ...r, spec: a.spec.id, nonGoal: true })),
  ])
  if (inherited.length) section('Inherited', inherited, (r) => (r.nonGoal ? `Non-goal: ${r.title}` : r.title), (r) => r.spec)
  if (history) {
    section('History', view.history, (r) =>
      r.outcome === 'superseded' ? `~~${r.title}~~ superseded by ${r.by}` : `~~${r.title}~~ removed: ${r.reason.replace(/^removed:\s*/i, '')}`,
    )
  }
  for (const sub of view.subspecs ?? []) lines.push(renderSpec(sub, { history, level: level + 1 }).trimEnd(), '')
  return `${lines.join('\n').trimEnd()}\n`
}

// Ids per bd query: under its 128 comparisons and 4096 bytes for ids of up to ~30 characters.
const QUERY_BATCH = 64

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
  const roots = findSpecs(bd(['list', '--all', '-n', '0', '-l', 'spec']), arg)
  // bd show gives the parent and edges that bd list and bd query leave out; each issue is fetched once.
  const issues = new Map()
  const load = (ids) => {
    const missing = [...new Set(ids)].filter((id) => !issues.has(id))
    // One id gives an object, several an array.
    if (missing.length) for (const i of [bd(['show', ...missing])].flat()) issues.set(i.id, i)
  }
  const get = (id) => {
    // An id bd cannot show (a stale parent) is treated as absent, not a failure of the whole command.
    try {
      load([id])
    } catch {
      return undefined
    }
    return issues.get(id)
  }
  // Direct children by bd query's `parent` (bd list --parent gives every descendant), many specs per query.
  const kidsOf = new Map()
  const prefetch = (ids) => {
    const missing = [...new Set(ids)].filter((id) => !kidsOf.has(id))
    for (let i = 0; i < missing.length; i += QUERY_BATCH) {
      const batch = missing.slice(i, i + QUERY_BATCH)
      const found = bd(['query', batch.map((id) => `parent = "${id}"`).join(' OR '), '-n', '0']).map((c) => c.id)
      load(found)
      for (const id of batch) kidsOf.set(id, [])
      for (const c of found) kidsOf.get(issues.get(c)?.parent)?.push(c)
    }
  }
  const kids = (id) => {
    prefetch([id])
    return kidsOf.get(id)
  }
  const views = specViews(roots, { get, kids, prefetch })
  process.stdout.write(json ? `${JSON.stringify(views, null, 2)}\n` : views.map((v) => renderSpec(v, { history })).join('\n'))
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2))
  } catch (e) {
    process.stderr.write(`spec: ${(e.stderr?.toString().trim() || e.message).split('\n')[0]}\n`)
    process.exitCode = 1
  }
}
