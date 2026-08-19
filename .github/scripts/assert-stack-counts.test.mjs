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
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
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
  const production = { numPassedTests: 23, numFailedTests: 0, numPendingTests: 14 };
  assert.equal(decide({ result: production, expectedPassed: 23, expectedPending: 14 }), null);
  // ...and the development expectation must NOT accept them, or the two call
  // sites' deliberately un-derived numbers would be interchangeable.
  assert.match(
    decide({ result: production, expectedPassed: 33, expectedPending: 4 }),
    /got 23\/14/,
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
  writeFileSync(
    join(dir, 'stack-results.json'),
    JSON.stringify({ numPassedTests: 33, numFailedTests: 0, numPendingTests: 4 }),
  );

  const images = readFileSync(join(WORKFLOWS, 'images.yml'), 'utf8');
  const line = /^\s*run: (node \.github\/scripts\/assert-stack-counts\.mjs [^\n]*)$/m.exec(images);
  assert.ok(line, 'images.yml no longer invokes the gate on one line — update this test');

  const out = execFileSync('bash', ['-c', line[1]], { cwd: dir, encoding: 'utf8' });
  assert.match(out, /passed=33 failed=0 pending=4/, 'the gate must PRINT, not merely exit 0');
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
});
