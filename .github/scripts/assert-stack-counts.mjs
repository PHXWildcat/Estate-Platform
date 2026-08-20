/**
 * The stack suite's EXACT-COUNT gate, as a script rather than as an inline
 * `node -e` body.
 *
 * WHY THIS IS A FILE. It used to be an inline `node -e '...'` in both
 * images.yml and stack.yml, carrying twenty lines of prose explaining where the
 * number came from. On 2026-08-19 one of those lines gained the word
 * `console's` — and an apostrophe CLOSES a single-quoted shell string. Bash
 * then parsed the remainder of the script as shell, found what looked like a
 * redirection, and — because redirections are set up BEFORE the command runs —
 * NEVER EXECUTED NODE AT ALL. The gate did not merely mis-assert; it did not
 * run, and had not run since the apostrophe landed. It went red, which is the
 * safe direction, but only by accident: the shell error is what failed the
 * step, and a quoting mistake that happened to still parse would have gone
 * green over an unevaluated assertion.
 *
 * The prose is the problem and the prose is worth keeping — this repo records
 * why every number is what it is. So the prose lives in YAML `#` comments at
 * the call sites, which no shell ever parses, and the LOGIC lives here, where
 * `node --test` can reach it. A `.github/scripts/*.test.mjs` glob in ci.yml
 * already runs the tests, so this arrives with one.
 *
 * WHAT IS SHARED AND WHAT IS NOT. The two call sites pass their OWN numbers.
 * images.yml runs the stack from BUILT IMAGES and stack.yml runs it from
 * `dist`, so a number derived from the other would stop being a measurement —
 * that reasoning is unchanged and is why this script takes the expected counts
 * as arguments rather than knowing any. Only the mechanism is shared.
 *
 * A FLOOR WITH SLACK IN IT is how two skipped assertions stay green; that is
 * measured history in this repo (M8 PR4), which is why this compares for
 * EQUALITY and not `>=`.
 */

import { readFileSync, realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

/**
 * The whole decision, as a pure function of the jest `--json` summary and the
 * two expected counts. Returns `null` when the run is good, or the error line
 * to print.
 *
 * A MALFORMED RESULT IS ITS OWN FAILURE, not a count mismatch: `undefined !== 33`
 * is true, so folding it in would report "expected 33, got undefined" and send
 * whoever reads it looking for a skipped spec instead of a broken result file.
 */
export function decide({ result, expectedPassed, expectedPending }) {
  for (const field of ['numPassedTests', 'numFailedTests', 'numPendingTests']) {
    if (typeof result?.[field] !== 'number') {
      return `jest result file is missing a numeric ${field} — the run did not produce a usable summary`;
    }
  }

  // Failures FIRST: "a spec failed" is a better answer than "the count moved",
  // and a failing suite usually moves the count too, so the count mismatch
  // would otherwise mask it.
  if (result.numFailedTests > 0) {
    return `stack test failures: ${result.numFailedTests} failed`;
  }

  if (result.numPassedTests !== expectedPassed || result.numPendingTests !== expectedPending) {
    return (
      `expected exactly ${expectedPassed} passed / ${expectedPending} pending, ` +
      `got ${result.numPassedTests}/${result.numPendingTests} — a spec skipped, or a ` +
      `test was added without updating this gate (and its twin: images.yml and ` +
      `stack.yml carry separate, deliberately un-derived numbers)`
    );
  }

  return null;
}

/** Reject a count that is not a non-negative integer, so a typo cannot become a silent expectation. */
export function parseExpected(raw, label) {
  if (!/^\d+$/.test(String(raw ?? ''))) {
    throw new Error(`${label} must be a non-negative integer, got ${JSON.stringify(raw)}`);
  }
  return Number(raw);
}

function main(argv) {
  const [file, passed, pending] = argv;
  if (!file) throw new Error('usage: assert-stack-counts.mjs <results.json> <passed> <pending>');

  const expectedPassed = parseExpected(passed, 'expected passed');
  const expectedPending = parseExpected(pending, 'expected pending');

  let result;
  try {
    result = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    // An ABSENT file is the "the suite did not run at all" case, which is the
    // one this step is named for, so it must never be confused with a parse
    // failure of a file that does exist.
    console.error(`::error::cannot read ${file} — the stack test did not run (${err.message})`);
    process.exit(1);
  }

  console.log(
    `passed=${result.numPassedTests} failed=${result.numFailedTests} pending=${result.numPendingTests}`,
  );

  const error = decide({ result, expectedPassed, expectedPending });
  if (error) {
    console.error(`::error::${error}`);
    process.exit(1);
  }
}

// Run main only when this file IS the entry point, so importing it from the
// test does not assert anything.
//
// Compared as URLs rather than by FILENAME. A name-keyed guard
// (`endsWith('assert-stack-counts.mjs')`) is silently wrong after a rename
// that updates the call sites and misses it: main never runs, node exits 0,
// and both exact-count gates pass without comparing anything. Measured — a
// renamed copy answered exit 0 for 99 passed / 7 pending against an expected
// 33 / 4. The test suite catches it (8 of 12 red), which is why it is a
// hardening rather than a hole; this makes the rename need no edit at all.
//
// Both sides are resolved before comparing, because each carries a different
// distortion. pathToFileURL handles the space that broke the extension
// packer's `file://` template. realpathSync handles the SYMLINK, which the
// packer's version still does not: node reports the real path in
// `import.meta.url` and the literal one in `process.argv[1]`, so invoking
// this file through /tmp on macOS (a symlink to /private/tmp) compared
// file:///private/tmp/... against file:///tmp/... and main never ran —
// measured, exit 0 and no output, on a mismatch that should have exited 1.
const entryPoint =
  process.argv[1] === undefined ? undefined : pathToFileURL(realpathSync(process.argv[1])).href;
if (import.meta.url === entryPoint) {
  main(process.argv.slice(2));
}
