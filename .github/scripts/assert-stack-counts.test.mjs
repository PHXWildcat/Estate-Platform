/**
 * Tests for the stack exact-count gate, on `node --test` for the reason its
 * sibling gives: these scripts run on the runner with bare node, and a test
 * needing the workspace toolchain is a test nobody runs.
 *
 * WHAT IS ACTUALLY AT RISK HERE, and it is not the arithmetic. The defect that
 * produced this file was not a wrong comparison — it was that the comparison
 * NEVER EXECUTED, because an apostrophe in a prose comment closed the
 * single-quoted shell string wrapping it and bash failed on a redirection
 * before running node. A unit test of `decide()` would have been green
 * throughout. So the cases below drive the SCRIPT AS A SUBPROCESS and assert
 * on its exit status and output. `execFileSync` spawns node directly, with NO
 * SHELL — and the shell is precisely the layer that failed, so that alone
 * would leave the real defect uncovered. The last case therefore takes the
 * `run:` line out of the workflow itself and executes it through bash. The
 * pure-function cases are underneath, for the messages.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { decide, parseExpected } from './assert-stack-counts.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'assert-stack-counts.mjs');
const WORKFLOWS = join(HERE, '..', 'workflows');
const DIR = mkdtempSync(join(tmpdir(), 'stack-counts-'));

/** Run the gate the way a workflow does, and report what the shell would see. */
function run({ results, passed, pending, file }) {
  const path = join(DIR, `${Math.random().toString(36).slice(2)}.json`);
  if (results !== undefined) writeFileSync(path, JSON.stringify(results));
  try {
    const stdout = execFileSync(
      process.execPath,
      [SCRIPT, file ?? path, String(passed), String(pending)],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    return { status: err.status, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

/**
 * The pair stack.yml passes for one profile, read from the workflow itself.
 *
 * Its shell picks production in the `then` arm and development in the `else`,
 * so the two pairs appear in that order and this returns the Nth. Arbitrary
 * fixtures below (GOOD and friends) are just inputs for the gate's own logic
 * and deliberately do NOT come from here — only the cases that make a claim
 * ABOUT a profile do, so that a legitimate count change moves one place.
 */
function expectedPair(profile) {
  const stack = readFileSync(join(WORKFLOWS, 'stack.yml'), 'utf8');
  const pairs = [...stack.matchAll(/passed=(\d+); pending=(\d+)/g)];
  assert.equal(pairs.length, 2, 'stack.yml must carry exactly two profile pairs');
  const [prod, dev] = pairs;
  const hit = profile === 'production' ? prod : dev;
  return [profile, Number(hit[1]), Number(hit[2])];
}

const GOOD = { numPassedTests: 33, numFailedTests: 0, numPendingTests: 4 };

test('THE GATE RUNS AT ALL — matching counts exit 0 and report what they saw', () => {
  const r = run({ results: GOOD, passed: 33, pending: 4 });
  assert.equal(r.status, 0);
  // The counts line is the evidence the gate evaluated rather than merely
  // exited; its absence is precisely what proved node never ran.
  assert.match(r.stdout, /passed=33 failed=0 pending=4/);
});

test('a moved PASSED count fails, and names both twins', () => {
  const r = run({ results: { ...GOOD, numPassedTests: 34 }, passed: 33, pending: 4 });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /expected exactly 33 passed \/ 4 pending, got 34\/4/);
  assert.match(r.stderr, /images\.yml and\s+stack\.yml/);
});

test('a moved PENDING count fails — a skipped spec is the thing this exists to catch', () => {
  const r = run({ results: { ...GOOD, numPendingTests: 6 }, passed: 33, pending: 4 });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /got 33\/6/);
});

test('a FAILING suite is reported as failures, not as a count mismatch', () => {
  const r = run({
    results: { numPassedTests: 30, numFailedTests: 3, numPendingTests: 4 },
    passed: 33,
    pending: 4,
  });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /stack test failures: 3 failed/);
  assert.doesNotMatch(r.stderr, /expected exactly/);
});

test('an ABSENT result file is "the suite did not run", never a count mismatch', () => {
  const r = run({ passed: 33, pending: 4, file: join(DIR, 'nope.json') });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /the stack test did not run/);
});

test('a MALFORMED summary is its own failure — undefined is not a count', () => {
  const r = run({ results: { totallyDifferent: true }, passed: 33, pending: 4 });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /missing a numeric numPassedTests/);
  assert.doesNotMatch(r.stderr, /expected exactly/);
});

test('a non-numeric EXPECTATION is refused rather than silently coerced', () => {
  const r = run({ results: GOOD, passed: 'thirty-three', pending: 4 });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /expected passed must be a non-negative integer/);
});

test('EQUALITY, not a floor: fewer passes than expected is a failure too', () => {
  // A `>=` here is how two `.skip`ed assertions stayed green in M8 PR4.
  assert.match(
    decide({
      result: { numPassedTests: 32, numFailedTests: 0, numPendingTests: 4 },
      expectedPassed: 33,
      expectedPending: 4,
    }),
    /got 32\/4/,
  );
});

test('the production profile passes its own numbers', () => {
  // READ from the workflows rather than restated here. These literals used to
  // be a THIRD copy of a pair maintained in two places, and M48 PR3 found them
  // the way such a copy is always found: the suite gained a test, both
  // workflows moved, and this file stayed on the old numbers — still green,
  // still describing a profile that no longer counted that way. images.yml's
  // own comment prescribes the remedy ("if a third consumer of this count ever
  // appears, derive it"), so both pairs come from the call sites.
  const [, prodPassed, prodPending] = expectedPair('production');
  const [, devPassed, devPending] = expectedPair('development');
  const production = {
    numPassedTests: prodPassed,
    numFailedTests: 0,
    numPendingTests: prodPending,
  };
  assert.equal(
    decide({ result: production, expectedPassed: prodPassed, expectedPending: prodPending }),
    null,
  );
  // ...and the development expectation must NOT accept them, or the two call
  // sites' deliberately un-derived numbers would be interchangeable.
  assert.match(
    decide({ result: production, expectedPassed: devPassed, expectedPending: devPending }),
    new RegExp(`got ${prodPassed}/${prodPending}`),
  );
});

test('parseExpected refuses what would become a silent expectation', () => {
  assert.equal(parseExpected('0', 'x'), 0);
  assert.throws(() => parseExpected('', 'x'), /must be a non-negative integer/);
  assert.throws(() => parseExpected(undefined, 'x'), /must be a non-negative integer/);
  assert.throws(() => parseExpected('-1', 'x'), /must be a non-negative integer/);
  assert.throws(() => parseExpected('3.5', 'x'), /must be a non-negative integer/);
});

test('THE WORKFLOWS INVOKE IT THROUGH A SHELL, and that line still works', () => {
  // The defect was in the SHELL, so a test that never starts one cannot see
  // its class. This takes each workflow's own `run:` line and executes it
  // through bash against a fabricated result file — the only case here that
  // exercises the layer that actually broke.
  const dir = mkdtempSync(join(tmpdir(), 'stackgate-'));
  mkdirSync(join(dir, '.github', 'scripts'), { recursive: true });
  copyFileSync(SCRIPT, join(dir, '.github', 'scripts', 'assert-stack-counts.mjs'));
  // The fabricated result is DERIVED from the numbers images.yml itself
  // passes, because this case is about the SHELL and not about the counts: a
  // hand-pinned pair here goes red every time the suite legitimately gains a
  // test, which reads as "the invocation broke" and is answered by editing the
  // fixture — the repair that quietly retires the case. What the counts are is
  // the sibling case below; that they still reach node through bash is this
  // one, and it must survive the numbers moving.
  const images = readFileSync(join(WORKFLOWS, 'images.yml'), 'utf8');
  const line = /^\s*run: (node \.github\/scripts\/assert-stack-counts\.mjs [^\n]*)$/m.exec(images);
  assert.ok(line, 'images.yml no longer invokes the gate on one line — update this test');
  const pair = /assert-stack-counts\.mjs stack-results\.json (\d+) (\d+)/.exec(line[1]);
  assert.ok(pair, 'images.yml must pass two literal counts on that line');
  const [passed, pending] = [Number(pair[1]), Number(pair[2])];

  writeFileSync(
    join(dir, 'stack-results.json'),
    JSON.stringify({ numPassedTests: passed, numFailedTests: 0, numPendingTests: pending }),
  );

  const out = execFileSync('bash', ['-c', line[1]], { cwd: dir, encoding: 'utf8' });
  assert.match(
    out,
    new RegExp(`passed=${passed} failed=0 pending=${pending}`),
    'the gate must PRINT, not merely exit 0',
  );
});

test('EACH WORKFLOW PASSES ITS OWN LITERAL NUMBERS — they are not derived', () => {
  // The sibling case proves the two profiles are not interchangeable, but it
  // never READ either workflow, so it could not tell whether the call sites
  // still carry their own numbers. images.yml runs the stack from BUILT IMAGES
  // and stack.yml from `dist`; a number derived from the other would stop
  // being a measurement.
  const images = readFileSync(join(WORKFLOWS, 'images.yml'), 'utf8');
  const stack = readFileSync(join(WORKFLOWS, 'stack.yml'), 'utf8');

  assert.match(
    images,
    /assert-stack-counts\.mjs stack-results\.json \d+ \d+/,
    'images.yml must pass literal counts',
  );
  const devPair = /assert-stack-counts\.mjs stack-results\.json (\d+) (\d+)/.exec(images);
  const prodPair = /passed=(\d+); pending=(\d+)/.exec(stack);
  assert.ok(prodPair, 'stack.yml must carry its own literal counts');
  assert.notDeepEqual(
    [devPair[1], devPair[2]],
    [prodPair[1], prodPair[2]],
    'the two profiles must not share one pair of numbers',
  );

  // ...and the two DEVELOPMENT pairs must AGREE. Un-derived is not the same as
  // unrelated: images.yml runs the suite from built images and stack.yml's dev
  // leg runs it from `dist`, so each number stays an independent measurement —
  // but they measure the same suite in the same profile, and a disagreement
  // means one of them was not updated. That is the exact failure the comment
  // beside each number describes ("forgetting the second is how that gate went
  // red once"), and until M48 PR3 nothing asserted it: the shell case above
  // caught it only by accident, through a hand-pinned fixture, and deriving
  // that fixture would have retired the accident silently.
  const stackDev = /passed=(\d+); pending=(\d+)\s*\n\s*fi/.exec(stack);
  assert.ok(stackDev, "stack.yml's development pair must be the last one before `fi`");
  assert.deepEqual(
    [devPair[1], devPair[2]],
    [stackDev[1], stackDev[2]],
    'images.yml and stack.yml disagree about the development counts — one was not updated',
  );
});

test('IT ASSERTS THROUGH A SYMLINKED PATH — the guard compares resolved paths', () => {
  // The main-module guard decides whether this script asserts anything at all,
  // so a guard that quietly fails to fire turns both exact-count gates into
  // steps that exit 0 without comparing. Two distortions can make the two
  // sides disagree, and only one of them is the famous one.
  //
  // `import.meta.url` reports the REAL path; `process.argv[1]` reports the
  // path as typed. Invoke the script through a symlinked directory and an
  // unresolved comparison sees file:///private/tmp/... against
  // file:///tmp/... — no output, exit 0, on input that must exit 1. macOS
  // reaches this by default, /tmp being a symlink to /private/tmp.
  const real = mkdtempSync(join(tmpdir(), 'assert-real-'));
  const link = join(mkdtempSync(join(tmpdir(), 'assert-link-')), 'via');
  symlinkSync(real, link);

  copyFileSync(SCRIPT, join(real, 'assert-stack-counts.mjs'));
  const results = join(real, 'stack-results.json');
  writeFileSync(
    results,
    JSON.stringify({ numPassedTests: 99, numFailedTests: 0, numPendingTests: 7 }),
  );

  let status = 0;
  let output = '';
  try {
    output = execFileSync(
      process.execPath,
      [join(link, 'assert-stack-counts.mjs'), results, '33', '4'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
  } catch (err) {
    status = err.status;
    output = `${err.stdout ?? ''}${err.stderr ?? ''}`;
  }

  assert.equal(status, 1, 'a mismatch reached through a symlink must still exit 1');
  assert.match(output, /expected exactly 33 passed \/ 4 pending/);
});

test('IT ASSERTS UNDER A DIFFERENT FILENAME — the guard is not name-keyed', () => {
  // The rename that breaks a name-keyed guard is a coordinated edit: move the
  // file, update both workflow call sites, and miss the `endsWith` three lines
  // from the bottom. Then main never runs and both exact-count gates exit 0
  // without comparing — measured on a renamed copy, which answered exit 0 for
  // 99 passed / 7 pending against an expected 33 / 4.
  //
  // This is the assertion that makes reverting to the name-keyed form fail.
  // Every other case in this file invokes the script under its own name, where
  // the two guards are indistinguishable.
  const dir = mkdtempSync(join(tmpdir(), 'assert-renamed-'));
  const renamed = join(dir, 'check-stack-counts.mjs');
  copyFileSync(SCRIPT, renamed);
  const results = join(dir, 'stack-results.json');
  writeFileSync(
    results,
    JSON.stringify({ numPassedTests: 99, numFailedTests: 0, numPendingTests: 7 }),
  );

  let status = 0;
  let output = '';
  try {
    output = execFileSync(process.execPath, [renamed, results, '33', '4'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    status = err.status;
    output = `${err.stdout ?? ''}${err.stderr ?? ''}`;
  }

  assert.equal(status, 1, 'a renamed copy must still assert');
  assert.match(output, /expected exactly 33 passed \/ 4 pending/);
});
