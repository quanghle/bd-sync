// The skill listing shows a workflow's meta.description + meta.whenToUse, cut at about 1,500 characters, so anything past
// that never reaches the caller. Per-arg notes live in each workflow's args comment instead; this keeps the listed text
// within budget for every workflow in .claude/workflows. A workflow script isn't a module, so this lifts the meta literal
// out of the source, like the other specs lift helpers.
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from './expect.mjs'

const BUDGET = 1200

const dir = fileURLToPath(new URL('../../.claude/workflows/', import.meta.url))
const workflows = readdirSync(dir)
	.filter((f) => f.endsWith('.js'))
	.toSorted()

it('finds the workflows', () => {
	expect(workflows).toEqual(expect.arrayContaining(['plan-implement-review.js', 'score-issue.js']))
})

describe.each(workflows)('%s', (file) => {
	it('keeps meta.description + meta.whenToUse within the skill listing budget', () => {
		const literal = readFileSync(dir + file, 'utf8').match(/^export const meta = (\{[\s\S]*?\n\})/m)?.[1]
		expect(literal, `${file} no longer starts with export const meta = {…}`).toBeTruthy()
		const meta = new Function(`return ${literal}`)()
		const length = meta.description.length + meta.whenToUse.length
		expect(
			length,
			`description + whenToUse is ${length} chars; the skill listing truncates at ~1,500, so keep it at most ${BUDGET} and move per-arg notes to the args comment`,
		).toBeLessThanOrEqual(BUDGET)
		expect(meta.whenToUse).toContain('args comment')
	})
})
