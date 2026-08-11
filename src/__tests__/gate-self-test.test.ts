/**
 * SOC-170 — the gate that guards the gates.
 *
 * This repo shipped seven spec violations to a public endpoint while its CI was
 * green, because the pipeline was stub-guard → tsc → build and ran no tests at
 * all. Nine suites existed; none executed. `tsconfig.json` also excluded the
 * tests, so `tsc --noEmit` never type-checked one either (measured:
 * `--listFiles | grep -c __tests__` returned 0).
 *
 * A CI step is a control like any other, and a control nobody can see break is
 * one nobody will notice being removed. So the steps assert their own presence
 * here. Delete the `npm test` step from ci.yml and this file goes red — which,
 * conveniently, requires the `npm test` step to notice.
 *
 * That circularity is the point rather than a flaw: the only way to silence
 * this file is to remove BOTH the step and the test, which is a deliberate act
 * visible in a diff, not an oversight.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const ci = readFileSync(join(repoRoot, '.github', 'workflows', 'ci.yml'), 'utf-8')
const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf-8')) as {
  scripts: Record<string, string>
}

describe('CI actually runs the tests', () => {
  test('ci.yml has a step that runs `npm test`', () => {
    // Matches `run: npm test` on its own line — not `npm test:coverage`, and
    // not a mention inside a comment.
    assert.match(
      ci,
      /^\s*run:\s*npm test\s*$/m,
      'ci.yml no longer runs `npm test` — every suite in this repo is decorative again',
    )
  })

  test('ci.yml type-checks the tests, which tsconfig.json excludes', () => {
    assert.match(
      ci,
      /tsc --noEmit -p tsconfig\.test\.json/,
      'without this pass, a type assertion inside a spec is never checked',
    )
  })

  test('the test step runs BEFORE the build step', () => {
    // A build that succeeds after a failed test is a wasted signal; ordering
    // makes the failure land on the cheapest step.
    const testAt = ci.search(/^\s*run:\s*npm test\s*$/m)
    const buildAt = ci.search(/^\s*run:\s*npm run build\s*$/m)
    assert.ok(testAt > 0 && buildAt > 0, 'both steps must exist')
    assert.ok(testAt < buildAt, 'npm test must run before npm run build')
  })
})

describe('coverage is measured, with a floor that can fail', () => {
  // Before this, coverage was not measured anywhere: no c8, no threshold, no
  // report. "Is this tested?" could only be answered by grepping which modules
  // a spec happens to import — which is how `server.ts` sat at zero coverage
  // through six security commits without anyone noticing.
  test('ci.yml runs the coverage check', () => {
    assert.match(
      ci,
      /^\s*run:\s*npm run test:coverage\s*$/m,
      'ci.yml no longer measures coverage — the floor stops applying silently',
    )
  })

  test('.c8rc.json enforces the floor rather than only reporting', () => {
    const c8 = JSON.parse(readFileSync(join(repoRoot, '.c8rc.json'), 'utf-8')) as {
      'check-coverage'?: boolean
      statements?: number
      branches?: number
      functions?: number
      lines?: number
    }
    // Without `check-coverage`, c8 prints a table and exits 0 — a report, not
    // a gate. This is the difference between the two.
    assert.equal(c8['check-coverage'], true, 'coverage must fail the build, not just print')
    for (const k of ['statements', 'branches', 'functions', 'lines'] as const) {
      assert.ok((c8[k] ?? 0) > 0, `${k} has no floor`)
    }
  })

  test('the floors are never lowered to make a build pass', () => {
    // A ratchet. These are the values the suite measured when the gate went in
    // (84.6 / 83.3 / 89.3 statements/branches/functions, floored a couple of
    // points below). Raising them is the intended edit; lowering one is how a
    // coverage gate quietly becomes decorative, so it reddens here first.
    const c8 = JSON.parse(readFileSync(join(repoRoot, '.c8rc.json'), 'utf-8')) as Record<
      string,
      number
    >
    const FLOOR = { statements: 78, branches: 76, functions: 85, lines: 78 }
    for (const [k, min] of Object.entries(FLOOR)) {
      assert.ok(
        c8[k] >= min,
        `.c8rc.json ${k} was lowered to ${c8[k]}; the ratchet floor is ${min}`,
      )
    }
  })
})

describe('the test script reaches every spec', () => {
  test('the glob is quoted, so node expands it recursively — not sh', () => {
    // `node --test src/**/*.test.ts` is expanded by sh, where `**` is NOT
    // globstar: it collapses to `src/*/*.test.ts`. That happens to match
    // `src/__tests__/` today, so a spec added at `src/foo.test.ts` or
    // `src/a/b/foo.test.ts` would be silently skipped — a test that never runs
    // is indistinguishable from one that passes.
    const script = pkg.scripts.test ?? ''
    assert.match(script, /--test/, 'the test script must invoke node --test')
    assert.match(
      script,
      /['"]src\/\*\*\/\*\.test\.ts['"]/,
      "the glob must be quoted so node performs recursive expansion, not sh",
    )
  })
})
