// Test helper, not a spec: reads the heredoc blocks out of a record prompt the way a shell does and runs them through real sh
// with a stub bd on PATH, so a spec shows what bd would receive and that nothing else ran. The specs that use it need sh, as
// plan-implement-review.record.spec.mjs already does.
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'

/**
 * Every heredoc in the prompt, as { command, first, tag, body }: command is its first line through its closing tag line, body
 * the lines between. The walk resumes after the closing line, as a shell would, so a body line that looks like an opener is
 * never taken for a block.
 */
export function blocks(prompt) {
	const lines = prompt.split('\n')
	const found = []
	for (let i = 0; i < lines.length; i++) {
		const tag = lines[i].match(/<<'([^']+)'$/)?.[1]
		if (!tag) continue
		const end = lines.indexOf(tag, i + 1)
		if (end < 0) throw new Error(`no closing line for: ${lines[i]}`)
		found.push({
			command: lines.slice(i, end + 1).join('\n'),
			first: lines[i],
			tag,
			body: lines.slice(i + 1, end).join('\n'),
		})
		i = end
	}
	return found
}

const STUB = `#!/bin/sh
for a in "$@"; do printf '%s\\0' "$a" >> "$BD_STUB/argv"; done
cat > "$BD_STUB/stdin"
exit "$BD_STUB_EXIT"
`

/**
 * Runs a block through sh in a scratch directory, with a stub bd that keeps its arguments and stdin and exits with exit. Returns
 * { status, stderr, argv, stdin, canary }, canary being whether the block made a file named canary in that directory.
 */
export function runBlock(block, exit = 0) {
	const dir = mkdtempSync(join(tmpdir(), 'record-block-'))
	try {
		const bin = join(dir, 'bin')
		mkdirSync(bin)
		writeFileSync(join(bin, 'bd'), STUB, { mode: 0o755 })
		writeFileSync(join(dir, 'argv'), '')
		writeFileSync(join(dir, 'stdin'), '')
		const { status, stderr } = spawnSync('sh', ['-c', block.command], {
			cwd: dir,
			encoding: 'utf8',
			env: { ...process.env, PATH: bin + delimiter + process.env.PATH, BD_STUB: dir, BD_STUB_EXIT: String(exit) },
		})
		return {
			status,
			stderr,
			argv: readFileSync(join(dir, 'argv'), 'utf8').split('\0').slice(0, -1),
			stdin: readFileSync(join(dir, 'stdin'), 'utf8'),
			canary: existsSync(join(dir, 'canary')),
		}
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
}

/** The text bd received: the argument after -d when there is one, else stdin, with trailing newlines removed. */
export function passed(r) {
	const i = r.argv.indexOf('-d')
	return (i < 0 ? r.stdin : r.argv[i + 1]).replace(/\n+$/, '')
}

/** Rows [name, text] for it.each: text that would run `touch canary`, or reach bd changed, if the shell did not take it literally. */
export const HOSTILE = [
	['a line EOF', 'a\nEOF\n)"\ntouch canary\n"\nb'],
	['a line equal to the tag', 'a\nBD_TEXT\ntouch canary\nb'],
	['lines equal to the first two tags', 'BD_TEXT\nBD_TEXT_X\ntouch canary\nb'],
	['a tag line with a carriage return', 'a\nBD_TEXT\r\ntouch canary\nb'],
	['unbalanced ) " and \'', `a ) " ' ) "\n)\ntouch canary\nb`],
	['backticks', '`touch canary`'],
	['command substitution', '$(touch canary)'],
	['parameter expansion', '${x:=$(touch canary)}'],
	['a trailing backslash', 'a\\'],
]
