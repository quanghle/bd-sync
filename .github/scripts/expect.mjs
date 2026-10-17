// The subset of vitest's expect the specs here use, over node:test and node:assert, so they run with `node --test`
// (this repository has no package.json). toEqual ignores undefined properties and toMatchObject matches a subset,
// recursively, with arrays matched element by element, as in vitest.
import assert from 'node:assert/strict'
import { format } from 'node:util'
import { describe as suite, it as test } from 'node:test'

export { afterEach, beforeEach } from 'node:test'

// it.each(rows)(title, fn) and describe.each(rows)(title, fn): each row spread into fn (a non-array row passed alone),
// the title formatted with printf-style placeholders (%s, %j, ...) from the row's values.
const each = (run) => (rows) => (title, fn) => {
  for (const row of rows) {
    const args = Array.isArray(row) ? row : [row]
    const n = (title.match(/%[sdifjoO]/g) || []).length
    run(format(title, ...args.slice(0, n)), () => fn(...args))
  }
}
export const it = Object.assign((...a) => test(...a), { each: each(test) })
export const describe = Object.assign((...a) => suite(...a), { each: each(suite) })

class Asymmetric {
  constructor(test, text) {
    this.test = test
    this.text = text
  }
}

const isObject = (v) => v !== null && typeof v === 'object'
const show = (v) => (v instanceof Asymmetric ? v.text : JSON.stringify(v))

function equals(a, b, subset) {
  if (b instanceof Asymmetric) return b.test(a)
  if (Object.is(a, b)) return true
  if (!isObject(a) || !isObject(b)) return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => equals(x, b[i], subset))
  if (a instanceof Date || b instanceof Date) return a instanceof Date && b instanceof Date && a.getTime() === b.getTime()
  if (a instanceof Map || b instanceof Map) {
    return a instanceof Map && b instanceof Map && equals([...a], [...b], subset)
  }
  if (a instanceof Set || b instanceof Set) {
    return a instanceof Set && b instanceof Set && equals([...a], [...b], subset)
  }
  const defined = (o) => Object.keys(o).filter((k) => o[k] !== undefined)
  const kb = defined(b)
  if (!subset) {
    const ka = defined(a)
    if (ka.length !== kb.length || ka.some((k) => !Object.hasOwn(b, k) || b[k] === undefined)) return false
  }
  return kb.every((k) => k in a && equals(a[k], b[k], subset))
}

const has = (v, x) => (typeof v === 'string' ? v.includes(x) : [...v].some((y) => Object.is(y, x)))

// note: expect's optional second argument, shown before a failure's own message.
function matchers(actual, negate, note) {
  const check = (ok, message) => {
    if (ok === negate) assert.fail(`${note ? `${note}: ` : ''}expected ${show(actual)} ${negate ? 'not ' : ''}${message}`)
  }
  return {
    toBe: (x) => check(Object.is(actual, x), `to be ${show(x)}`),
    toEqual: (x) => check(equals(actual, x, false), `to equal ${show(x)}`),
    toMatchObject: (x) => check(equals(actual, x, true), `to match ${show(x)}`),
    toContain: (x) => check(has(actual, x), `to contain ${show(x)}`),
    toContainEqual: (x) => check([...actual].some((y) => equals(y, x, false)), `to contain an item equal to ${show(x)}`),
    toHaveLength: (n) => check(actual?.length === n, `to have length ${n}`),
    toHaveProperty: (k) => check(isObject(actual) && k in actual, `to have property ${k}`),
    toMatch: (re) => check(typeof re === 'string' ? actual.includes(re) : re.test(actual), `to match ${re}`),
    toBeNull: () => check(actual === null, 'to be null'),
    toBeUndefined: () => check(actual === undefined, 'to be undefined'),
    toBeTruthy: () => check(!!actual, 'to be truthy'),
    toBeGreaterThan: (n) => check(actual > n, `to be > ${n}`),
    toBeLessThan: (n) => check(actual < n, `to be < ${n}`),
    toBeLessThanOrEqual: (n) => check(actual <= n, `to be <= ${n}`),
    toBeCloseTo: (n, digits = 2) => check(Math.abs(actual - n) < 10 ** -digits / 2, `to be close to ${n}`),
    toThrow: (want) => {
      let thrown = null
      try {
        actual()
      } catch (e) {
        thrown = e
      }
      const msg = thrown?.message ?? ''
      const ok =
        thrown !== null &&
        (want === undefined || (want instanceof RegExp ? want.test(msg) : typeof want === 'string' ? msg.includes(want) : thrown instanceof want))
      if (ok === negate) assert.fail(`expected function ${negate ? 'not ' : ''}to throw${want ? ` ${want}` : ''}${thrown ? `, got: ${msg}` : ''}`)
    },
  }
}

// expect(promise).resolves / .rejects: each matcher awaits the promise, then checks its value or, for rejects, a function
// throwing its reason (so toThrow works on it).
const settled = (promise, rejects) =>
  new Proxy(
    {},
    {
      get: (_, name) =>
        async (...a) => {
          let value
          let failed = false
          try {
            value = await promise
          } catch (e) {
            value = e
            failed = true
          }
          if (failed !== rejects) assert.fail(`expected the promise to ${rejects ? 'reject' : 'resolve'}, got ${show(value?.message ?? value)}`)
          const subject = rejects && name === 'toThrow' ? () => { throw value } : value
          return matchers(subject, false)[name](...a)
        },
    },
  )

export function expect(actual, note) {
  return { ...matchers(actual, false, note), not: matchers(actual, true, note), resolves: settled(actual, false), rejects: settled(actual, true) }
}
expect.stringMatching = (re) => new Asymmetric((v) => typeof v === 'string' && re.test(v), `stringMatching(${re})`)
expect.arrayContaining = (items) =>
  new Asymmetric((v) => Array.isArray(v) && items.every((x) => v.some((y) => equals(y, x, false))), `arrayContaining(${show(items)})`)
