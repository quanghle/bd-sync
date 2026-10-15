import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from './expect.mjs'
import {
	COMPUTED_TASK,
	agentFacts,
	aggregate,
	bandOf,
	encodeProject,
	matchFindings,
	modelClass,
	observe,
	pairPasses,
	parseLabel,
	passesOf,
	projectDirs,
	promptOf,
	render,
	runOf,
	validatorsOf,
	verdictOf,
} from './reviewer-catch.mjs'

const RELAY = '[Workflow harness — user request] The user asked for this workflow:\n  implement squid-x'
const task = (text) => `${COMPUTED_TASK} The task text below was computed at runtime by a workflow script. The computed task text follows:\n${text.replace(/^/gm, '  ')}`
const user = (content) => ({ type: 'user', message: { role: 'user', content } })
const assistant = (model = 'claude-opus-5-5', n = 0) => ({
	type: 'assistant',
	requestId: `req${n}`,
	timestamp: `2026-10-15T00:00:0${n}Z`,
	message: { model, usage: { input_tokens: 1, output_tokens: 1 }, content: [{ type: 'text', text: 'ok' }] },
})
const relayed = (text) => promptOf([user(RELAY), user(task(text)), assistant()])
const apiRequest = (effort) => ({ type: 'api-request', params: { output_config: { effort } } })

describe('parseLabel', () => {
	it.each([
		['review:code:r0', { kind: 'code', round: 0, type: 'cheap' }],
		['review:a11y:confirm-r1@strong', { kind: 'a11y', round: 1, type: 'confirm', level: 'strong' }],
		['review:code:r0@strong', { kind: 'code', round: 0, type: 'cheap', level: 'strong' }],
		['review:code:r2@shadow:sonnet-medium', { kind: 'code', round: 2, type: 'shadow', shadow: { model: 'sonnet', effort: 'medium' } }],
		['review:code:r0@shadow:claude-haiku-4-5-low', { kind: 'code', round: 0, type: 'shadow', shadow: { model: 'claude-haiku-4-5', effort: 'low' } }],
		['validate:r0:F1', null],
		['coder:S1', null],
		[undefined, null],
	])('%s', (label, want) => expect(parseLabel(label)).toEqual(want))
})

describe('modelClass', () => {
	it.each([
		['opus', 'opus'],
		['claude-sonnet-5-5', 'sonnet'],
		['claude-haiku-4-5-20251001', 'haiku'],
		['fable', 'fable'],
		['gpt-x', 'gpt-x'],
		[undefined, 'unknown'],
		[null, 'unknown'],
	])('%s is %s', (id, want) => expect(modelClass(id)).toBe(want))
})

describe('promptOf', () => {
	it('takes the computed task, not the user-request relay before it', () => {
		expect(promptOf([user(RELAY), user(task('Review the diff.')), assistant()])).toBe(task('Review the diff.'))
	})

	it('takes a single computed-task entry as it is', () => {
		expect(promptOf([user([{ type: 'text', text: task('a') }]), assistant()])).toBe(task('a'))
	})

	it('joins the leading user entries when no computed-task entry is there', () => {
		expect(promptOf([user('one'), user([{ type: 'text', text: 'two' }, { type: 'image' }]), assistant()])).toBe('one\n\ntwo')
	})

	it('is null without a transcript', () => {
		expect(promptOf([])).toBeNull()
		expect(promptOf(null)).toBeNull()
	})

	it('ignores user entries after the first assistant entry', () => {
		expect(promptOf([user('first'), assistant(), user(task('later'))])).toBe('first')
	})
})

describe('agentFacts', () => {
	it('takes the model from meta and the effort from the transcript', () => {
		expect(agentFacts({ model: 'opus' }, [apiRequest('high'), user(task('x')), assistant('claude-opus-5-5')])).toEqual({ model: 'opus', effort: 'high', prompt: task('x') })
	})

	it('falls back to the transcript model, as a class', () => {
		expect(agentFacts({ agentType: 'workflow-subagent' }, [user('x'), assistant('claude-sonnet-5-5', 0), assistant('claude-sonnet-5-5', 1)]).model).toBe('sonnet')
	})

	it('is unknown without meta or transcript', () => {
		expect(agentFacts(null, null)).toEqual({ model: 'unknown', effort: 'unknown', prompt: null })
	})
})

// ---------- journal fixtures ----------
const started = (agentId, label) => ({ type: 'started', key: `k-${agentId}`, agentId, label, phase: 'Review' })
const result = (agentId, value) => ({ type: 'result', key: `k-${agentId}`, agentId, result: value })
const finding = (file, line, claim) => ({ file, line, claim, severity: 'minor', category: 'correctness', evidence: 'e' })
const factsFrom = (table) => (id) => table[id] ?? { model: 'unknown', effort: 'unknown', prompt: null }
const pass = (over) => ({ journal: 'wf1', kind: 'code', round: 0, type: 'cheap', model: 'sonnet', effort: 'medium', prompt: 'P', findings: [], failed: false, ...over })

describe('passesOf', () => {
	it('parses string results, fails a pass without a result, and dedupes agents', () => {
		const journal = {
			wf: 'wf1',
			entries: [
				{ type: 'launched' },
				started('a1', 'review:code:r0'),
				started('a1', 'review:code:r0'),
				result('a1', JSON.stringify({ findings: [finding('a.ts', 1, 'x')] })),
				started('a2', 'review:code:confirm-r0@strong'),
				started('a3', 'coder:S1'),
				result('a3', { summary: 'done' }),
				started('a4', 'review:code:r0@shadow:sonnet-low'),
				result('a4', 'not json'),
			],
		}
		const passes = passesOf(journal, factsFrom({ a1: { model: 'haiku', effort: 'low', prompt: 'P' } }))
		expect(passes.map((p) => [p.label, p.failed, p.findings?.length ?? null])).toEqual([
			['review:code:r0', false, 1],
			['review:code:confirm-r0@strong', true, null],
			['review:code:r0@shadow:sonnet-low', true, null],
		])
		expect(passes[0]).toMatchObject({ journal: 'wf1', kind: 'code', round: 0, type: 'cheap', model: 'haiku', effort: 'low', prompt: 'P' })
		expect(passes[1]).toMatchObject({ model: 'unknown', effort: 'unknown', prompt: null })
	})
})

describe('pairPasses', () => {
	it('pairs a cheap pass with its confirmation when the prompts are the same', () => {
		const { pairs, skipped } = pairPasses([pass({ label: 'r0' }), pass({ label: 'c0', type: 'confirm', level: 'strong', model: 'opus' })])
		expect(pairs.map((p) => [p.source, p.a.label, p.b.label, p.prompt])).toEqual([['confirm', 'r0', 'c0', 'same']])
		expect(skipped).toEqual({ differentPrompt: 0, failed: 0 })
	})

	it('skips a focused round against a full confirmation', () => {
		const { pairs, skipped } = pairPasses([pass({ round: 1, prompt: 'focused' }), pass({ round: 1, type: 'confirm', prompt: 'full' })])
		expect(pairs).toEqual([])
		expect(skipped.differentPrompt).toBe(1)
	})

	it('still skips it when both transcripts open with the same user-request relay', () => {
		const { pairs, skipped } = pairPasses([pass({ round: 1, prompt: relayed('focused re-review') }), pass({ round: 1, type: 'confirm', prompt: relayed('full review') })])
		expect(pairs).toEqual([])
		expect(skipped.differentPrompt).toBe(1)
	})

	it('pairs a shadow with the real pass, but not with an escalated one', () => {
		const { pairs } = pairPasses([pass({ label: 'r0' }), pass({ label: 'r0@strong', level: 'strong' }), pass({ label: 'sh', type: 'shadow', model: 'haiku', effort: 'low' })])
		expect(pairs.map((p) => [p.source, p.a.label, p.b.label])).toEqual([['shadow', 'r0', 'sh']])
	})

	it('pairs every cheap pass, escalated ones too, with the confirmation', () => {
		const { pairs } = pairPasses([pass({ label: 'r0' }), pass({ label: 'r0@strong', level: 'strong' }), pass({ label: 'c0', type: 'confirm' })])
		expect(pairs.map((p) => p.a.label)).toEqual(['r0', 'r0@strong'])
	})

	it('pairs nothing across kinds, rounds or journals, and never a failed pass', () => {
		const { pairs, skipped } = pairPasses([
			pass({}),
			pass({ type: 'confirm', kind: 'a11y' }),
			pass({ type: 'confirm', round: 1 }),
			pass({ type: 'confirm', journal: 'wf2' }),
			pass({ kind: 'req', failed: true, findings: null }),
			pass({ kind: 'req', type: 'confirm' }),
		])
		expect(pairs).toEqual([])
		expect(skipped).toEqual({ differentPrompt: 0, failed: 1 })
	})

	it('keeps a pair whose prompt is unknown as unchecked', () => {
		const { pairs } = pairPasses([pass({ prompt: null }), pass({ type: 'confirm' })])
		expect(pairs.map((p) => p.prompt)).toEqual(['unchecked'])
	})
})

describe('matchFindings', () => {
	it('matches lines up to 5 apart in the same file', () => {
		expect(matchFindings([finding('a.ts', 10, 'x')], [finding('a.ts', 13, 'y')]).matches).toEqual([[0, 0]])
	})

	it('does not match lines 7 apart, even with the same claim', () => {
		expect(matchFindings([finding('a.ts', 10, 'same claim text')], [finding('a.ts', 17, 'same claim text')])).toEqual({ matches: [], aOnly: [0], bOnly: [0] })
	})

	it('matches an absolute path with a relative one by basename', () => {
		expect(matchFindings([finding('/Users/q/wt/src/lib/a.ts', 4, 'x')], [finding('src/lib/a.ts', 4, 'y')]).matches).toEqual([[0, 0]])
		expect(matchFindings([finding('src/lib/a.ts', 4, 'x')], [finding('src/lib/b.ts', 4, 'x')]).matches).toEqual([])
	})

	it('compares claims when a line is missing', () => {
		const a = finding('a.ts', null, 'The focus ring is clipped by overflow hidden on the menu')
		expect(matchFindings([a], [finding('a.ts', 40, 'Overflow hidden on the menu clips the focus ring')]).matches).toEqual([[0, 0]])
		expect(matchFindings([a], [finding('a.ts', 40, 'Missing test for keyboard navigation in submenus')]).matches).toEqual([])
	})

	it('matches one to one, best score first', () => {
		const got = matchFindings([finding('a.ts', 10, 'x'), finding('a.ts', 12, 'y')], [finding('a.ts', 12, 'z')])
		expect(got).toEqual({ matches: [[1, 0]], aOnly: [0], bOnly: [] })
	})
})

const VALIDATOR = (claim) =>
	task(
		`You are the controller validating a code-review finding.\n\nTask being implemented: squid-x\n\nFinding:\n[F1] serious correctness — /Users/q/wt/src/lib/a.ts:12\n  Claim: ${claim}\n  Evidence: line 12 does it\n\nDECISION LEDGER: (none)`,
	)

describe('validatorsOf', () => {
	const claim = 'The menu closes\non a second click.'
	const journal = {
		wf: 'wf1',
		entries: [started('v1', 'validate:r0:F1'), result('v1', { valid: true, blocking: false, reasoning: 'r' }), started('v2', 'validate:r0:F2'), result('v2', null)],
	}

	it('reads the finding from an indented computed-task prompt and joins its verdict', () => {
		const verdicts = validatorsOf(journal, factsFrom({ v1: { prompt: VALIDATOR(claim) } }))
		expect(verdicts.size).toBe(1)
		expect(verdictOf(finding('src/lib/a.ts', 12, 'The menu closes on a second click.'), verdicts)).toEqual({ valid: true, blocking: false })
		expect(verdictOf(finding('src/lib/a.ts', 12, 'Another claim'), verdicts)).toBeNull()
	})

	it('reads it behind a user-request relay', () => {
		const prompt = promptOf([user(RELAY), user(VALIDATOR(claim)), assistant()])
		const verdicts = validatorsOf(journal, factsFrom({ v1: { prompt } }))
		expect(verdictOf(finding('a.ts', 3, 'The menu closes on a second click.'), verdicts)).toEqual({ valid: true, blocking: false })
	})
})

describe('observe and aggregate', () => {
	const A = [finding('a.ts', 10, 'one'), finding('a.ts', 50, 'two'), finding('b.ts', 5, 'three')]
	const B = [finding('a.ts', 11, 'one again'), finding('c.ts', 1, 'four')]
	const verdicts = new Map()
	const judge = (f, valid) => verdicts.set(`${f.file}\0${f.claim}`, { valid, blocking: false })
	judge(A[0], true) // matched to B[0], which inherits it
	judge(A[1], false)
	judge(B[1], true) // A misses it
	const pair = { source: 'confirm', a: pass({ findings: A }), b: pass({ findings: B, model: 'opus', effort: 'high' }), prompt: 'same' }

	it('counts both sides in both views', () => {
		const [a, b] = observe(pair, 3, verdicts)
		expect(a).toEqual({
			model: 'sonnet',
			effort: 'medium',
			vs: 'opus/high',
			band: 3,
			all: { raised: 3, matched: 1, missed: 1 },
			validated: { raised: 1, matched: 1, missed: 1, unverified: 1 },
		})
		expect(b).toEqual({
			model: 'opus',
			effort: 'high',
			vs: 'sonnet/medium',
			band: 3,
			all: { raised: 2, matched: 1, missed: 2 },
			validated: { raised: 2, matched: 1, missed: 0, unverified: 0 },
		})
		const rows = aggregate([a, b])
		expect(rows.all.find((r) => r.model === 'sonnet/medium')).toMatchObject({ pairs: 1, raised: 3, matched: 1, missed: 1, union: 4, catch: 0.75, thin: true, sameLevel: false })
		expect(rows.all.find((r) => r.model === 'opus/high')).toMatchObject({ raised: 2, missed: 2, union: 4, catch: 0.5, sameLevel: false })
		expect(rows.all.find((r) => r.model === 'sonnet/medium')).not.toHaveProperty('agreement')
		expect(rows.validated.find((r) => r.model === 'sonnet/medium')).toMatchObject({ raised: 1, matched: 1, missed: 1, union: 2, catch: 0.5, unverified: 1 })
		expect(rows.validated.find((r) => r.model === 'opus/high')).toMatchObject({ raised: 2, missed: 0, catch: 1, unverified: 0 })
	})

	it('lets a shadow finding inherit its matched partner verdict', () => {
		const shadow = { source: 'shadow', a: pass({ findings: [A[0]] }), b: pass({ type: 'shadow', model: 'haiku', effort: 'low', findings: [finding('a.ts', 9, 'unjudged'), finding('z.ts', 1, 'new')] }), prompt: 'same' }
		const [, b] = observe(shadow, 'unknown', verdicts)
		expect(b.validated).toEqual({ raised: 1, matched: 1, missed: 0, unverified: 1 })
	})

	const obs = (band, n) => Array.from({ length: n }, () => observe(pair, band, verdicts)[0])

	it('flags a row thin under 5 pairs and sorts by band', () => {
		const rows = aggregate([...obs('unknown', 1), ...obs(4, 4), ...obs(2, 5)]).all
		expect(rows.map((r) => [r.band, r.pairs, r.thin])).toEqual([
			[2, 5, false],
			[4, 4, true],
			['unknown', 1, true],
		])
		expect(rows[0]).toMatchObject({ raised: 15, matched: 5, missed: 5, catch: 0.75 })
	})

	const same = { source: 'confirm', a: pass({ findings: A, model: 'opus', effort: 'high' }), b: pass({ findings: B, model: 'opus', effort: 'high' }), prompt: 'same' }

	it('counts a pair once when both sides share a model and effort', () => {
		const rows = aggregate(observe(same, 3, verdicts)).all
		expect(rows).toHaveLength(1)
		expect(rows[0]).toMatchObject({ model: 'opus/high', vs: 'opus/high', pairs: 1, raised: 5, missed: 3, thin: true })
		expect(Object.keys(rows[0])).not.toContain('pair')
		expect(rows[0]).toMatchObject({ sameLevel: true, catch: null, matched: 2, raised: 5, agreement: 0.4 })
		const validated = aggregate(observe(same, 3, verdicts)).validated[0]
		expect(validated).toMatchObject({ sameLevel: true, catch: null, raised: 3, matched: 2 })
		expect(validated.agreement).toBeCloseTo(2 / 3)
	})

	it('gives agreement 0 to a same-level pair with no shared finding', () => {
		const a = pass({ model: 'opus', effort: 'high', findings: [finding('x.ts', 1, 'p')] })
		const b = pass({ model: 'opus', effort: 'high', findings: [finding('y.ts', 1, 'q')] })
		const rows = aggregate(observe({ source: 'confirm', a, b, prompt: 'same' }, 3, verdicts)).all
		expect(rows).toHaveLength(1)
		expect(rows[0]).toMatchObject({ raised: 2, matched: 0, agreement: 0, catch: null, sameLevel: true })
	})

	it('gives agreement null to a same-level pair that raised nothing', () => {
		const a = pass({ model: 'opus', effort: 'high', findings: [] })
		const b = pass({ model: 'opus', effort: 'high', findings: [] })
		const rows = aggregate(observe({ source: 'confirm', a, b, prompt: 'same' }, 3, verdicts)).all
		expect(rows[0]).toMatchObject({ raised: 0, agreement: null, catch: null, sameLevel: true })
	})

	it('flags three same-model pairs thin', () => {
		const rows = aggregate(Array.from({ length: 3 }, () => observe(same, 3, verdicts)).flat())
		expect(rows.all.map((r) => [r.pairs, r.thin])).toEqual([[3, true]])
		expect(rows.validated.map((r) => [r.pairs, r.thin])).toEqual([[3, true]])
	})
})

describe('render', () => {
	it('prints both tables without any claim text or path', () => {
		const pair = { source: 'confirm', a: pass({ findings: [finding('secret/path.ts', 3, 'Secret claim text')] }), b: pass({ type: 'confirm', model: 'opus', effort: 'high' }), prompt: 'same' }
		const observations = observe(pair, 2, new Map())
		const out = render({
			journals: 1,
			passes: 2,
			failed: 0,
			pairs: [{ source: 'confirm', prompt: 'same', band: 2 }],
			skipped: { differentPrompt: 3, failed: 0 },
			rows: aggregate(observations),
		})
		expect(out).toContain('# Reviewer catch rate')
		expect(out).toContain('## All findings')
		expect(out).toContain('## Validated findings only')
		expect(out).toContain('| band | model/effort | vs | pairs | raised | matched | missed | catch | agree | thin |')
		expect(out).toContain('| 2 | sonnet/medium | opus/high | 1 | 1 | 0 | 0 | 100% | – | thin |')
		expect(out).toContain('3 with different prompts')
		expect(out).toContain('catch = raised / union')
		expect(out).toContain('50% to 100% by construction')
		expect(out).toContain('agree = matched / raised')
		expect(out).not.toContain('(union - missed) / union')
		expect(out).not.toMatch(/Secret claim|secret\/path|path\.ts/)
	})

	it('shows agreement and no catch on same-level rows', () => {
		const A = [finding('a.ts', 10, 'one'), finding('a.ts', 50, 'two'), finding('b.ts', 5, 'three')]
		const B = [finding('a.ts', 11, 'one again'), finding('c.ts', 1, 'four')]
		const verdicts = new Map()
		verdicts.set(`${A[0].file}\0${A[0].claim}`, { valid: true, blocking: false })
		verdicts.set(`${A[1].file}\0${A[1].claim}`, { valid: false, blocking: false })
		verdicts.set(`${B[1].file}\0${B[1].claim}`, { valid: true, blocking: false })
		const rows = aggregate(observe({ source: 'confirm', a: pass({ findings: A, model: 'opus', effort: 'high' }), b: pass({ findings: B, model: 'opus', effort: 'high' }), prompt: 'same' }, 3, verdicts))
		const out = render({ journals: 1, passes: 2, failed: 0, pairs: [{ source: 'confirm', prompt: 'same', band: 3 }], skipped: { differentPrompt: 0, failed: 0 }, rows })
		expect(out).toContain('| 3 | opus/high | opus/high | 1 | 5 | 2 | 3 | – | 40% | thin |')
		expect(out).toContain('| 3 | opus/high | opus/high | 1 | 3 | 2 | 1 | – | 67% | thin |')
	})
})

describe('bandOf', () => {
	const issues = {
		'squid-c': { metadata: { score: { complexity: 4 }, score_judge: { complexity: 3 }, complexity_estimate: { score: 2 } } },
		'squid-j': [{ metadata: { score_judge: { complexity: 3 }, complexity_estimate: { score: 2 } } }],
		'squid-e': { metadata: { complexity_estimate: { score: 2 } } },
		'squid-n': { metadata: {} },
		'squid-r.1': { metadata: { playbook: { role: 'run' }, score_judge: { complexity: 5 } } },
		'squid-r.1.implement': { metadata: { playbook: { role: 'step', run: 'squid-r.1' } } },
	}
	const stub = () => {
		const calls = []
		const bd = (args) => {
			calls.push(args)
			if (!(args[1] in issues)) throw new Error('issue not_found')
			return issues[args[1]]
		}
		return { calls, bd }
	}

	it('takes the confirmed, else judged, else estimated complexity', () => {
		const { bd } = stub()
		expect(bandOf('squid-c', bd)).toEqual({ band: 4, source: 'confirmed' })
		expect(bandOf('squid-j', bd)).toEqual({ band: 3, source: 'judged' })
		expect(bandOf('squid-e', bd)).toEqual({ band: 2, source: 'estimate' })
		expect(bandOf('squid-n', bd)).toEqual({ band: 'unknown', source: null })
	})

	it('resolves a step to its run', () => {
		const { calls, bd } = stub()
		expect(bandOf('squid-r.1.implement', bd)).toEqual({ band: 5, source: 'judged' })
		expect(calls).toEqual([
			['show', 'squid-r.1.implement'],
			['show', 'squid-r.1'],
		])
	})

	it('is unknown when bd throws', () => {
		expect(
			bandOf('squid-x', () => {
				throw new Error('server unreachable')
			}),
		).toEqual({ band: 'unknown', source: null })
	})

	it('never passes an id that is not a plain issue id to bd', () => {
		const { calls, bd } = stub()
		expect(bandOf('x; rm -rf', bd)).toEqual({ band: 'unknown', source: null })
		expect(bandOf('X/../y', bd)).toEqual({ band: 'unknown', source: null })
		expect(calls).toEqual([])
	})

	it('shows each id once per cache', () => {
		const { calls, bd } = stub()
		const cache = new Map()
		bandOf('squid-r.1.implement', bd, cache)
		bandOf('squid-r.1', bd, cache)
		bandOf('squid-r.1.implement', bd, cache)
		bandOf('squid-missing', bd, cache)
		bandOf('squid-missing', bd, cache)
		expect(calls.map((c) => c[1])).toEqual(['squid-r.1.implement', 'squid-r.1', 'squid-missing'])
	})
})

describe('runOf', () => {
	it('takes the review step as its run, else the issue, else one named in a prompt', () => {
		expect(runOf({ reviewStep: 'squid-a.1.review', issue: 'squid-a' }, [])).toBe('squid-a.1')
		expect(runOf({ issue: 'squid-a' }, ['(bd issue: squid-b)'])).toBe('squid-a')
		expect(runOf(null, [null, 'Review it.\n\n(bd issue: squid-b.1.implement; read it with bd show)'])).toBe('squid-b.1.implement')
		expect(runOf({}, ['no issue here', null])).toBeNull()
	})
})

describe('projectDirs', () => {
	let dir
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'reviewer-catch-projects-'))
		for (const d of ['-Users-q-squi', '-Users-q-squi--claude-worktrees-wt', '-Users-q-squiggle', '-Users-q-squi-other']) mkdirSync(join(dir, d))
	})
	afterEach(() => rmSync(dir, { recursive: true, force: true }))

	it('takes the main checkout and its worktrees, not a sibling with the same prefix', () => {
		expect(encodeProject('/Users/q/squi/.claude/worktrees/wt')).toBe('-Users-q-squi--claude-worktrees-wt')
		expect(projectDirs(dir, '/Users/q/squi').toSorted()).toEqual(['-Users-q-squi', '-Users-q-squi--claude-worktrees-wt'])
	})
})

// One agent: its journal entries, meta and transcript (an optional relay, the computed task, one request at effort).
const agent = (dir, id, { label, model, effort, prompt, relay = false, value }) => {
	writeFileSync(join(dir, `agent-${id}.meta.json`), JSON.stringify(model ? { agentType: 'workflow-subagent', model } : { agentType: 'workflow-subagent' }))
	const lines = [apiRequest(effort), ...(relay ? [user(RELAY)] : []), user(task(prompt)), assistant(model === 'sonnet' ? 'claude-sonnet-5-5' : 'claude-opus-5-5')]
	writeFileSync(join(dir, `agent-${id}.jsonl`), lines.map((l) => JSON.stringify(l)).join('\n'))
	return [started(id, label), result(id, typeof value === 'string' ? value : JSON.stringify(value))]
}

describe('reviewer-catch CLI', () => {
	const ROOT = '/fake/squi'
	const CLAIM = 'Fixture claim the menu loses focus'
	let tmp
	let projects
	let bin

	const workflow = (project, session, wf, record, agents) => {
		const dir = join(projects, project, session, 'subagents', 'workflows', wf)
		mkdirSync(dir, { recursive: true })
		mkdirSync(join(projects, project, session, 'workflows'), { recursive: true })
		writeFileSync(join(projects, project, session, 'workflows', `${wf}.json`), JSON.stringify(record))
		const entries = [{ type: 'launched' }, ...agents.flatMap(([id, a]) => agent(dir, id, a))]
		writeFileSync(join(dir, 'journal.jsonl'), entries.map((e) => JSON.stringify(e)).join('\n'))
	}

	beforeEach(() => {
		tmp = mkdtempSync(join(tmpdir(), 'reviewer-catch-cli-'))
		projects = join(tmp, 'projects')
		bin = join(tmp, 'bin')
		mkdirSync(bin)
		const found = finding('/fake/squi/src/lib/a.ts', 12, CLAIM)
		const review = 'Review the diff of squid-a.\n\n(bd issue: squid-a.1.implement; read it)'
		workflow(encodeProject(ROOT), 's1', 'wf_ir', { workflowName: 'implement-review', args: JSON.stringify({ issue: 'squid-a', reviewStep: 'squid-a.1.review' }) }, [
			['r0', { label: 'review:code:r0', model: 'sonnet', effort: 'medium', prompt: review, relay: true, value: { findings: [found] } }],
			['c0', { label: 'review:code:confirm-r0@strong', model: 'opus', effort: 'high', prompt: review, relay: true, value: { findings: [{ ...found, file: 'src/lib/a.ts', line: 14 }, finding('b.ts', 3, 'other')] } }],
			['v0', { label: 'validate:r0:F1', model: 'opus', effort: 'high', prompt: VALIDATOR(CLAIM), relay: true, value: { valid: true, blocking: true, reasoning: 'r' } }],
		])
		workflow(encodeProject(join(ROOT, '.claude/worktrees/wt')), 's2', 'wf_pir', { workflowName: 'plan-implement-review', args: { issue: 'squid-b' } }, [
			['p0', { label: 'review:code:r0', effort: 'high', prompt: 'Review squid-b.', value: { findings: [] } }],
			['p1', { label: 'review:code:r0@shadow:sonnet-medium', model: 'sonnet', effort: 'medium', prompt: 'Review squid-b.', value: { findings: [finding('c.ts', 1, 'shadow only')] } }],
		])
		// A stand-in for bd that logs every call and knows both runs.
		writeFileSync(
			join(bin, 'bd'),
			[
				'#!/bin/sh',
				`echo "$*" >> "${bin}/calls"`,
				'case " $* " in',
				`  *" show squid-a.1 "*) echo '${JSON.stringify({ metadata: { score_judge: { complexity: 3 } } })}' ;;`,
				`  *" show squid-b "*) echo '${JSON.stringify([{ metadata: { complexity_estimate: { score: 2 } } }])}' ;;`,
				`  *) echo 'issue not_found' >&2; exit 3 ;;`,
				'esac',
				'',
			].join('\n'),
		)
		chmodSync(join(bin, 'bd'), 0o755)
	})
	afterEach(() => rmSync(tmp, { recursive: true, force: true }))

	const run = (...args) => {
		const script = fileURLToPath(new URL('./reviewer-catch.mjs', import.meta.url))
		try {
			return execFileSync('node', [script, '--projects', projects, '--root', ROOT, ...args], { encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, stdio: ['ignore', 'pipe', 'pipe'] })
		} catch (e) {
			throw new Error(`exit ${e.status}: ${e.stderr}`, { cause: e })
		}
	}

	it('reports both tables with bands from bd, and no claim text', () => {
		const out = run()
		expect(out).toContain('2 journals, 4 review passes (0 failed). 2 pairs: 1 cheap vs confirm, 1 real vs shadow.')
		expect(out).toContain('| 2 | opus/high | sonnet/medium | 1 | 0 | 0 | 1 | 0% | – | thin |')
		expect(out).toContain('| 3 | sonnet/medium | opus/high | 1 | 1 | 1 | 1 | 50% | – | thin |')
		expect(out).not.toMatch(/Fixture claim|shadow only|a\.ts|squid-a/)
	})

	it('prints JSON with the validator verdict joined, and only shows issues in bd', () => {
		const got = JSON.parse(run('--json'))
		expect(got.pairs).toHaveLength(2)
		const confirm = got.pairs.find((p) => p.source === 'confirm')
		expect(confirm).toMatchObject({ run: 'squid-a.1', workflow: 'implement-review', band: 3, bandSource: 'judged', prompt: 'same', matched: 1, aOnly: 0, bOnly: 1 })
		expect(confirm.a).toEqual({ label: 'review:code:r0', model: 'sonnet', effort: 'medium', findings: 1 })
		expect(got.pairs.find((p) => p.source === 'shadow')).toMatchObject({ run: 'squid-b', band: 2, bandSource: 'estimate', a: { model: 'opus', effort: 'high' } })
		// The r0 finding is valid by its own verdict, the confirmation's match by inheritance; 'other' was never validated.
		expect(got.rows.validated.find((r) => r.band === 3 && r.model === 'sonnet/medium')).toMatchObject({ raised: 1, matched: 1, missed: 0, unverified: 0, sameLevel: false })
		expect(got.rows.validated.find((r) => r.band === 3 && r.model === 'opus/high')).toMatchObject({ raised: 1, matched: 1, unverified: 1 })
		const calls = readFileSync(join(bin, 'calls'), 'utf8').trim().split('\n')
		expect(calls).toEqual([`-C ${ROOT} show squid-a.1 --json`, `-C ${ROOT} show squid-b --json`])
	})
})
