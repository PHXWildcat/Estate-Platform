/**
 * Tests for the image vulnerability gate, on `node --test` so this needs no
 * dependency and no jest project — these scripts run on the runner with bare
 * node, and a test that needed the workspace toolchain to run would be a test
 * nobody runs.
 *
 * WHY THIS FILE EXISTS AT ALL. ci.yml said out loud that `gate-image-scan.mjs`,
 * "the script that decides whether a vulnerability blocks a merge, has never
 * had a test", and ended "there is no excuse for the next one either". It was
 * the only script under .github/scripts without a companion. What that absence
 * hid is the first half of this file: four separate report shapes that made the
 * gate answer `application (blocking): 0` and exit 0 without a scan having
 * happened.
 *
 * WHAT IS ACTUALLY AT RISK. Not the blocking arithmetic — that arm goes red
 * loudly and someone reads it. The risk is the arm that passes, because a gate
 * that says "nothing to block" when nothing was scanned is indistinguishable
 * from a clean image, ships the build, and is believed. So the refusal cases
 * that used to pass carry a POSITIVE CONTROL beside them: a report that must pass
 * asserted in the same run as one that must be refused. A gate that refuses
 * everything and a gate that discriminates look identical if you only test the
 * refusals.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  EXIT_BLOCKED,
  EXIT_CLEAN,
  EXIT_MISUSE,
  EXIT_REFUSED,
  MAX_DB_AGE_DAYS,
  classify,
  main,
  readReport,
  scanRefusal,
} from './gate-image-scan.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'gate-image-scan.mjs');
// REAL time, captured once. This was a literal date, and the spawn tests below
// invoke the script for real — where `now` is `Date.now()`, not this constant —
// so the fixture's `built` aged against the wall clock and every "clean report"
// case was scheduled to start FAILING seven days after the date was written,
// reddening CI for everyone with a staleness refusal about a fixture. A test
// that breaks the build on a date is worse than the bug it guards.
const NOW = Date.now();
const dirs = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const scratch = () => {
  const d = mkdtempSync(join(tmpdir(), 'gate-image-scan-'));
  dirs.push(d);
  return d;
};

/** A report shaped like grype v0.97.1's real output, which this repo has on file. */
const report = (over = {}) => ({
  matches: [],
  source: { type: 'image' },
  descriptor: {
    name: 'grype',
    db: {
      status: {
        schemaVersion: 'v6.1.9',
        built: new Date(NOW - 3600_000).toISOString(),
        valid: true,
      },
    },
  },
  ...over,
});

const match = (type, severity = 'High') => ({
  vulnerability: { id: 'CVE-2026-0001', severity, fix: { state: 'fixed' } },
  artifact: { name: 'thing', version: '1.0.0', type },
});

/**
 * Run main() capturing what it wrote, so exit code AND token are both assertable.
 *
 * GITHUB_STEP_SUMMARY is redirected to a scratch file for the duration. The gate
 * APPENDS to whatever that variable names, so running this suite on a runner
 * wrote ten fabricated reports into the real job summary — three of them
 * announcing a blocking CVE that does not exist.
 */
const run = (argv, now = NOW) => {
  const out = [];
  const errs = [];
  const prior = process.env.GITHUB_STEP_SUMMARY;
  process.env.GITHUB_STEP_SUMMARY = join(scratch(), 'summary.md');
  try {
    const code = main(argv, { now, log: (l) => out.push(l), err: (l) => errs.push(l) });
    return { code, out: out.join('\n'), err: errs.join('\n') };
  } finally {
    if (prior === undefined) delete process.env.GITHUB_STEP_SUMMARY;
    else process.env.GITHUB_STEP_SUMMARY = prior;
  }
};

/** Spawn the script with the ambient job summary removed, for the same reason. */
const spawnGate = (args) => {
  const env = { ...process.env };
  delete env.GITHUB_STEP_SUMMARY;
  return spawnSync(process.execPath, args, { encoding: 'utf8', env });
};

const withReport = (body) => {
  const f = join(scratch(), 'grype.json');
  writeFileSync(f, typeof body === 'string' ? body : JSON.stringify(body));
  return f;
};

// ---------------------------------------------------------------------------
// The four shapes that used to pass. Each is paired with the positive control
// in the same assertion block, so "it refuses everything" cannot masquerade as
// a fix.
// ---------------------------------------------------------------------------

test('a report with no `matches` key is REFUSED, while a real empty scan passes', () => {
  assert.equal(run([withReport({}), 'operator-web']).code, EXIT_REFUSED);
  assert.match(run([withReport({}), 'operator-web']).err, /REFUSED.*no `matches` key/s);
  // POSITIVE CONTROL: the same gate, the same run, on a scan that did happen.
  const clean = run([withReport(report()), 'operator-web']);
  assert.equal(clean.code, EXIT_CLEAN);
  assert.match(clean.out, /application \(blocking\): 0/);
});

test('grype reporting its own database invalid is REFUSED, not read as zero findings', () => {
  const body = report();
  body.descriptor.db.status.valid = false;
  const r = run([withReport(body), 'operator-web']);
  assert.equal(r.code, EXIT_REFUSED);
  assert.match(r.err, /REFUSED.*database reported itself invalid/s);
  assert.equal(run([withReport(report()), 'operator-web']).code, EXIT_CLEAN);
});

test('a JSON array where the report object belongs is REFUSED', () => {
  const r = run([withReport([]), 'operator-web']);
  assert.equal(r.code, EXIT_REFUSED);
  assert.match(r.err, /REFUSED.*JSON array/s);
});

test('a schema rename of `matches` is REFUSED rather than counted as clean', () => {
  const body = report();
  delete body.matches;
  body.Matches = [];
  const r = run([withReport(body), 'operator-web']);
  assert.equal(r.code, EXIT_REFUSED);
  assert.match(r.err, /REFUSED.*no `matches` key/s);
});

// ---------------------------------------------------------------------------
// The shapes that were already fatal, but undiagnosed.
// ---------------------------------------------------------------------------

test('the 0-byte report from the #177 failure names the image and the scanner', () => {
  const r = run([withReport(''), 'operator-web']);
  assert.equal(r.code, EXIT_REFUSED);
  assert.match(r.err, /operator-web: REFUSED/);
  assert.match(r.err, /empty \(0 bytes\)/);
  // The old failure mode: a raw SyntaxError naming a line number in this file.
  assert.doesNotMatch(r.err, /SyntaxError|Unexpected end of JSON/);
});

test('an absent report file is diagnosed rather than dying on ENOENT', () => {
  const r = run([join(scratch(), 'nope.json'), 'operator-web']);
  assert.equal(r.code, EXIT_REFUSED);
  assert.match(r.err, /no readable report/);
  assert.match(r.err, /ENOENT/);
});

test('a truncated report is diagnosed as bad JSON, naming the path', () => {
  const f = withReport('{"matches":[');
  const r = run([f, 'operator-web']);
  assert.equal(r.code, EXIT_REFUSED);
  assert.match(r.err, /not valid JSON/);
  assert.ok(r.err.includes(f));
});

// ---------------------------------------------------------------------------
// Staleness — the case where `valid: true` is true and meaningless.
// ---------------------------------------------------------------------------

test('a database older than the limit is REFUSED, and one inside it passes', () => {
  const stale = report();
  stale.descriptor.db.status.built = new Date(
    NOW - (MAX_DB_AGE_DAYS + 1) * 86_400_000,
  ).toISOString();
  assert.equal(run([withReport(stale), 'operator-web']).code, EXIT_REFUSED);
  assert.match(run([withReport(stale), 'operator-web']).err, /built .* days ago/);

  const fresh = report();
  fresh.descriptor.db.status.built = new Date(
    NOW - (MAX_DB_AGE_DAYS - 1) * 86_400_000,
  ).toISOString();
  assert.equal(run([withReport(fresh), 'operator-web']).code, EXIT_CLEAN);
});

test('the staleness check reads db.status.built, not the undefined db.built', () => {
  // THE DISCRIMINATING CASE, not an assertion about the fixture. A stale nested
  // date with a FRESH decoy at the wrong path: an implementation reading
  // `descriptor.db.built` sees a current timestamp and passes, one reading
  // `descriptor.db.status.built` refuses. Asserting only that the decoy path is
  // undefined survived exactly the mutation the test is named for.
  const decoyed = report();
  decoyed.descriptor.db.status.built = new Date(
    NOW - (MAX_DB_AGE_DAYS + 3) * 86_400_000,
  ).toISOString();
  decoyed.descriptor.db.built = new Date(NOW).toISOString();
  assert.match(scanRefusal(decoyed, NOW), /days ago/);

  // And the NaN half: an unreadable date must refuse, not compare false and pass.
  const noDate = report();
  noDate.descriptor.db.status.built = undefined;
  assert.match(scanRefusal(noDate, NOW), /no readable build date/);

  // POSITIVE CONTROL: the same shape, fresh, passes.
  assert.equal(scanRefusal(report(), NOW), null);
});

test('a report naming no database at all is REFUSED', () => {
  const body = report();
  delete body.descriptor;
  assert.match(scanRefusal(body, NOW), /names no usable vulnerability database/);
});

// ---------------------------------------------------------------------------
// The ownership split, which must keep working exactly as before.
// ---------------------------------------------------------------------------

test('an application-dependency high blocks, and says so under its own token', () => {
  const r = run([withReport(report({ matches: [match('npm')] })), 'operator-web']);
  assert.equal(r.code, EXIT_BLOCKED);
  assert.match(r.err, /high\/critical vulnerability in an application dependency — bump it/);
});

test('base-image highs are reported, not blocking', () => {
  const r = run([withReport(report({ matches: [match('deb'), match('binary')] })), 'operator-web']);
  assert.equal(r.code, EXIT_CLEAN);
  assert.match(r.out, /application \(blocking\): 0/);
  assert.match(r.out, /base image \(reported\): {2}2/);
});

test('low and medium severities are neither blocked nor reported', () => {
  const { severe } = classify(report({ matches: [match('npm', 'Medium'), match('npm', 'Low')] }));
  assert.equal(severe.length, 0);
});

test('more than twenty base findings are capped with a count of the remainder', () => {
  const many = Array.from({ length: 23 }, () => match('deb'));
  const r = run([withReport(report({ matches: many })), 'operator-web']);
  assert.equal(r.code, EXIT_CLEAN);
  assert.match(r.out, /base {6}… 3 more/);
});

// ---------------------------------------------------------------------------
// The two outcomes must not share a token — different remedies.
// ---------------------------------------------------------------------------

test('a refusal and a real finding are distinguishable on the wire', () => {
  const refused = run([withReport({}), 'operator-web']).err;
  const blocked = run([withReport(report({ matches: [match('npm')] })), 'operator-web']).err;
  assert.match(refused, /REFUSED/);
  assert.doesNotMatch(blocked, /REFUSED/);
  assert.match(refused, /the scan did not run/);
  assert.doesNotMatch(refused, /bump it/);
});

test('a missing image name is refused rather than silently labelled', () => {
  const r = run([withReport(report())]);
  assert.equal(r.code, EXIT_MISUSE);
  assert.match(r.err, /usage/);
  // The old default was the literal string 'image', which produced a plausible
  // report about nothing nameable.
  assert.doesNotMatch(r.out, /^\nimage:/);
});

test('a BOM-prefixed report still parses', () => {
  const f = withReport('﻿' + JSON.stringify(report()));
  assert.equal(readReport(f).error, undefined);
  assert.equal(run([f, 'operator-web']).code, EXIT_CLEAN);
});

// ---------------------------------------------------------------------------
// The entry point. A main guard that never fires looks exactly like a pass.
// ---------------------------------------------------------------------------

test('invoked as a script it exits non-zero and prints the refusal', () => {
  const r = spawnGate([SCRIPT, withReport({}), 'operator-web']);
  assert.equal(r.status, EXIT_REFUSED);
  assert.match(r.stderr, /REFUSED/);
});

test('invoked as a script on a clean report it exits 0 and prints the split', () => {
  const r = spawnGate([SCRIPT, withReport(report()), 'operator-web']);
  assert.equal(r.status, EXIT_CLEAN);
  assert.match(r.stdout, /application \(blocking\): 0/);
});

test('the entry-point guard survives being reached through a symlink', () => {
  // The distortion assert-stack-counts.mjs documents: node reports the real
  // path in import.meta.url and the literal one in process.argv[1], so on macOS
  // /tmp (a symlink to /private/tmp) main silently never ran — exit 0, no
  // output, on input that must exit 1.
  const link = join(scratch(), 'linked.mjs');
  symlinkSync(SCRIPT, link);
  const r = spawnGate([link, withReport({}), 'operator-web']);
  assert.equal(r.status, EXIT_REFUSED);
  assert.match(r.stderr, /REFUSED/);
});

test('the caller can tell a retryable refusal from a finding it must not retry', () => {
  // images.yml retries EXIT_REFUSED and only that. If a blocking finding shared
  // the refusal's code the loop would rescan three times and report it late; if
  // a refusal shared the finding's code the loop would never retry at all — the
  // bug this whole change exists to remove, moved one layer out.
  const codes = [EXIT_CLEAN, EXIT_BLOCKED, EXIT_REFUSED, EXIT_MISUSE];
  assert.equal(new Set(codes).size, codes.length);
  assert.notEqual(EXIT_BLOCKED, EXIT_REFUSED);
  assert.equal(
    run([withReport(report({ matches: [match('npm')] })), 'operator-web']).code,
    EXIT_BLOCKED,
  );
  assert.equal(run([withReport({}), 'operator-web']).code, EXIT_REFUSED);
});

// ---------------------------------------------------------------------------
// The fourth outcome: the gate falling over. Found by this PR's own review,
// which is the defect the PR exists to remove standing one path over.
// ---------------------------------------------------------------------------

test('a null db.status refuses instead of throwing past the guard', () => {
  // `descriptor?.db?.status` stops at undefined, so a serialised nil status
  // arrives as null and sailed past an `=== undefined` check into a TypeError.
  const body = report();
  body.descriptor.db.status = null;
  const r = run([withReport(body), 'operator-web']);
  assert.equal(r.code, EXIT_REFUSED);
  assert.match(r.err, /names no usable vulnerability database/);
});

test('a match the gate cannot read is REFUSED, never counted as ignorable', () => {
  // `BLOCKING_SEVERITIES.has(undefined)` is false, so an unreadable finding used
  // to land silently in the non-blocking bucket — the absent-`matches` defect
  // one level in.
  for (const [label, m] of [
    ['a null entry', null],
    ['no severity', { artifact: { type: 'npm' } }],
    [
      'a severity outside the vocabulary',
      { vulnerability: { severity: 'CRITICAL' }, artifact: { type: 'npm' } },
    ],
    ['no artifact type', { vulnerability: { severity: 'High' } }],
  ]) {
    const r = run([withReport(report({ matches: [m] })), 'operator-web']);
    assert.equal(r.code, EXIT_REFUSED, label);
    assert.match(r.err, /cannot read/, label);
  }
  // POSITIVE CONTROL: a legible finding is still classified, not refused.
  assert.equal(
    run([withReport(report({ matches: [match('npm')] })), 'operator-web']).code,
    EXIT_BLOCKED,
  );
});

test('an unwritable job summary is a refusal, not a blocking finding', () => {
  const prior = process.env.GITHUB_STEP_SUMMARY;
  process.env.GITHUB_STEP_SUMMARY = join(scratch(), 'no', 'such', 'dir', 'summary.md');
  try {
    const out = [];
    const errs = [];
    const code = main([withReport(report()), 'operator-web'], {
      now: NOW,
      log: (l) => out.push(l),
      err: (l) => errs.push(l),
    });
    // It printed `application (blocking): 0` and then exited under the code
    // meaning "a high/critical vulnerability in an application dependency".
    assert.match(out.join('\n'), /application \(blocking\): 0/);
    assert.equal(code, EXIT_REFUSED);
    assert.match(errs.join('\n'), /the gate itself failed/);
  } finally {
    if (prior === undefined) delete process.env.GITHUB_STEP_SUMMARY;
    else process.env.GITHUB_STEP_SUMMARY = prior;
  }
});

// ---------------------------------------------------------------------------
// Refusal reasons that had no case.
// ---------------------------------------------------------------------------

test('a non-array `matches` is refused under its own reason', () => {
  const r = run([withReport(report({ matches: {} })), 'operator-web']);
  assert.equal(r.code, EXIT_REFUSED);
  assert.match(r.err, /`matches` is not an array/);
});

test('a database built in the future is accepted, not refused for negative age', () => {
  // Clock skew between the runner and the database publisher must not read as
  // staleness — the check is one-sided on purpose.
  const skewed = report();
  skewed.descriptor.db.status.built = new Date(NOW + 3 * 86_400_000).toISOString();
  assert.equal(scanRefusal(skewed, NOW), null);
});

test('the staleness boundary is exclusive, and one second past it refuses', () => {
  const at = report();
  at.descriptor.db.status.built = new Date(NOW - MAX_DB_AGE_DAYS * 86_400_000).toISOString();
  assert.equal(scanRefusal(at, NOW), null);
  const past = report();
  past.descriptor.db.status.built = new Date(
    NOW - MAX_DB_AGE_DAYS * 86_400_000 - 1000,
  ).toISOString();
  assert.match(scanRefusal(past, NOW), /days ago/);
});

// ---------------------------------------------------------------------------
// The constants are only worth anything if the CALLER agrees with them.
// ---------------------------------------------------------------------------

test('the fixture is fresh against the REAL clock, so this suite cannot expire', () => {
  // Guards the regression directly: if NOW is ever re-pinned to a literal date,
  // this fails the moment that date is MAX_DB_AGE_DAYS old rather than silently
  // reddening the spawn tests later.
  assert.equal(scanRefusal(report(), Date.now()), null);
});

test('images.yml retries the exit code this file calls EXIT_REFUSED', () => {
  // The caller compares against a LITERAL. Renumbering EXIT_REFUSED here would
  // leave every other test green while the workflow silently stopped retrying —
  // the two halves of one contract, in two files, with nothing joining them.
  const wf = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'workflows', 'images.yml'),
    'utf8',
  );
  const step = wf.slice(wf.indexOf('- name: Scan image for vulnerabilities'));
  const m = /\[ "\$rc" -ne (\d+) \]/.exec(step);
  assert.ok(
    m,
    'the scan step no longer compares $rc against a literal — this fence has lost its anchor',
  );
  assert.equal(Number(m[1]), EXIT_REFUSED);
  // And the loop must not treat the blocking code as retryable.
  assert.notEqual(Number(m[1]), EXIT_BLOCKED);
});
