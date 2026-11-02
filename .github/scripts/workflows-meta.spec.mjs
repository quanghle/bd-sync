// The skill listing shows a workflow's meta.description + meta.whenToUse, cut at about 1,500 characters, so anything past
// that never reaches the caller. Per-arg notes live in each workflow's args comment instead; this keeps the listed text
// within budget for every workflow in .claude/workflows. A workflow script isn't a module, so this lifts the meta literal
// out of the source, like the other specs lift helpers. Every workflow and extension is also held to writing its bd record
// commands whole, with no <Text> left for an agent to compose and no heredoc inside "$(...)", which bash 3.2 can't keep text in.
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from './expect.mjs'

const BUDGET = 1200

const root = fileURLToPath(new URL('../../', import.meta.url))
const dir = `${root}.claude/workflows/`
const workflows = readdirSync(dir)
	.filter((f) => f.endsWith('.js'))
	.toSorted()
const extensions = readdirSync(`${root}.github/extensions`, { withFileTypes: true })
	.filter((entry) => entry.isDirectory())
	.map((entry) => `.github/extensions/${entry.name}/extension.mjs`)
	.filter((f) => existsSync(root + f))
	.toSorted()
const sources = [...workflows.map((f) => `.claude/workflows/${f}`), ...extensions]

it('finds the workflows', () => {
	expect(workflows).toEqual(expect.arrayContaining(['plan-implement-review.js', 'score-issue.js']))
})

it('finds the sources that write record prompts, so a moved file does not pass by matching nothing', () => {
	expect(sources).toEqual(
		expect.arrayContaining([
			'.claude/workflows/plan-implement-review.js',
			'.claude/workflows/score-issue.js',
			'.github/extensions/plan-implement-review/extension.mjs',
			'.github/extensions/score-issue/extension.mjs',
		]),
	)
})

describe.each(sources)('%s', (file) => {
	it('leaves no record text for an agent to compose and no heredoc in a command substitution', () => {
		const source = readFileSync(root + file, 'utf8')
		expect(source).not.toContain(`<<'EOF'`)
		expect(source).not.toContain('<Text>')
		expect(source).not.toMatch(/\$\([^)]*<</)
	})
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
