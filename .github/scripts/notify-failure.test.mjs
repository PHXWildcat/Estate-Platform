/**
 * Tests for the failure notifier's decision logic, on `node --test` so this
 * needs no dependency and no jest project — these scripts run on the runner with
 * bare node, and a test that needed the workspace toolchain to run would be a
 * test nobody runs.
 *
 * WHAT IS ACTUALLY AT RISK HERE. The notifier's whole reason to exist is that
 * seventeen consecutive red days went unnoticed; the way it fails is not by
 * staying silent but by becoming noise — seventeen issues instead of one — at
 * which point it is ignored exactly like the runs it replaced. So the dedup
 * decision is the thing under test, including the cases that make it dedup the
 * WRONG thing: sharing one issue between two workflows, or hijacking an
 * unrelated open report.
 *
 * AND THE OTHER WAY IT FAILS IS BY NOT RUNNING AT ALL, which is the second half
 * of this file. Producing nothing is this script's normal state — it speaks
 * only when a scheduled gate fails — so a main guard that never fires looks
 * exactly like a green week. That is the one failure nobody thinks to question,
 * in the one component that exists so that nobody has to.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { decide, issueBody, issueTitle } from './notify-failure.mjs';

const TITLE = issueTitle('Security');

test('with nothing on record, it opens an issue', () => {
  assert.deepEqual(decide({ title: TITLE, openIssues: [], closedIssues: [] }), {
    action: 'create',
  });
});

test('an open report of the same failure is commented on, never duplicated', () => {
  assert.deepEqual(
    decide({ title: TITLE, openIssues: [{ number: 7, title: TITLE }], closedIssues: [] }),
    { action: 'comment', number: 7 },
  );
});

test('a report someone closed prematurely is reopened, not paralleled', () => {
  assert.deepEqual(
    decide({ title: TITLE, openIssues: [], closedIssues: [{ number: 5, title: TITLE }] }),
    { action: 'reopen', number: 5 },
  );
});

test('open beats closed, so a stale closed row cannot resurrect', () => {
  assert.deepEqual(
    decide({
      title: TITLE,
      openIssues: [{ number: 9, title: TITLE }],
      closedIssues: [{ number: 5, title: TITLE }],
    }),
    { action: 'comment', number: 9 },
  );
});

test('another workflow’s open report is not hijacked', () => {
  // Both callers share this script, so a title-insensitive match would file
  // Images failures onto the Security issue and vice versa — one of them would
  // then look resolved while it was still failing.
  assert.deepEqual(
    decide({
      title: TITLE,
      openIssues: [{ number: 8, title: issueTitle('Images') }],
      closedIssues: [],
    }),
    { action: 'create' },
  );
});

test('titles are per-workflow, which is what keeps the two callers separate', () => {
  assert.notEqual(issueTitle('Security'), issueTitle('Images'));
});

test('the body carries what makes the notification actionable', () => {
  const body = issueBody({
    workflow: 'Security',
    runUrl: 'https://github.com/o/r/actions/runs/1',
    sha: 'abcdef1234567890',
    event: 'schedule',
    details: 'scans whole history',
  });
  // Without the run URL the issue says only that something broke.
  assert.match(body, /\/actions\/runs\/1/);
  assert.match(body, /abcdef1/);
  assert.match(body, /scans whole history/);
});

test('an absent details line leaves no dangling section', () => {
  const body = issueBody({
    workflow: 'W',
    runUrl: 'u',
    sha: '1234567890',
    event: 'schedule',
    details: '   ',
  });
  assert.ok(!body.endsWith('\n'), body);
});

/* ------------------------------------------------------------------ *
 * THE MAIN GUARD FIRES ON IDENTITY, NOT ON THE SPELLING OF THE PATH.
 *
 * Every case below is driven as a real subprocess, because the guard is a
 * property of how node was INVOKED and nothing observable from inside this
 * process can stand in for that.
 *
 * THE OBSERVABLE IS DELIBERATE AND NETWORK-FREE: run with no environment and
 * main throws `GITHUB_TOKEN is required` before it reaches a single `fetch`, so
 * exit 1 with that message means main RAN and exit 0 with nothing means it did
 * not. That is the shape the image smoke tests already use — prove the
 * fail-fast posture in the shipped artifact rather than mock it — and here the
 * silent exit 0 IS the regression, so asserting on the status alone would pass
 * straight over the defect.
 * ------------------------------------------------------------------ */

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'notify-failure.mjs');

// A base with no symlink component anywhere, so each case adds exactly one
// distortion. `os.tmpdir()` is ITSELF symlinked on macOS (/var -> /private/var),
// which would otherwise make every case quietly a symlink case as well.
const BASE = mkdtempSync(join(realpathSync(tmpdir()), 'notify-guard-'));
after(() => rmSync(BASE, { recursive: true, force: true }));

/** Stage a copy of the script at `relative` under BASE and return its path. */
function stage(relative) {
  const target = join(BASE, relative);
  mkdirSync(dirname(target), { recursive: true });
  cpSync(SCRIPT, target);
  return target;
}

/** Invoke a path with NO environment; report whether main ran. */
function invoke(entry) {
  const r = spawnSync(process.execPath, [entry], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '' },
  });
  return { ranMain: r.status !== 0 && /GITHUB_TOKEN is required/.test(r.stderr), raw: r };
}

function why(raw) {
  return `expected main to run; status=${raw.status} stderr=${raw.stderr}`;
}

test('the staging is honest: BASE carries no symlink and no space of its own', () => {
  // Anti-vacuity for every case below. Without this the "space" and "renamed"
  // cases could be passing because of a symlink nobody put there on purpose,
  // and a fix that handled only symlinks would look complete.
  assert.equal(realpathSync(BASE), BASE);
  assert.ok(!BASE.includes(' '), BASE);
});

test('main runs when this file IS the entry point', () => {
  const { ranMain, raw } = invoke(SCRIPT);
  assert.ok(ranMain, why(raw));
});

for (const [label, relative] of [
  // The rename the old guard could not survive: every call site updated, the
  // guard silently left behind.
  ['a RENAMED copy', 'renamed/notify-ci-failure.mjs'],
  ['a path containing a SPACE', 'has space/notify-failure.mjs'],
]) {
  test(`main runs through ${label}`, () => {
    const entry = stage(relative);
    assert.equal(realpathSync(entry), entry, 'this case must not also be a symlink case');
    const { ranMain, raw } = invoke(entry);
    assert.ok(ranMain, why(raw));
  });
}

test('main runs through a SYMLINKED DIRECTORY', () => {
  const real = stage('linked-dir/real/notify-failure.mjs');
  const link = join(BASE, 'linked-dir', 'link');
  symlinkSync(dirname(real), link, 'dir');
  const entry = join(link, 'notify-failure.mjs');
  assert.notEqual(realpathSync(entry), entry, 'this case must actually traverse a symlink');
  const { ranMain, raw } = invoke(entry);
  assert.ok(ranMain, why(raw));
});

test('main runs through a SYMLINK POINTING AT IT UNDER ANOTHER NAME', () => {
  // The name-keyed guard could not see through this either: argv[1] ends with
  // `runner.mjs`, and it is still this script that node is executing.
  const real = stage('linked-file/notify-failure.mjs');
  const link = join(BASE, 'linked-file', 'runner.mjs');
  symlinkSync(real, link, 'file');
  const { ranMain, raw } = invoke(link);
  assert.ok(ranMain, why(raw));
});

test('main does NOT run when the module is merely imported', () => {
  // The guard's whole purpose, and the reason the tests above can import
  // `decide` at the top of this file without filing a GitHub issue.
  //
  // The importer is named to end with the same suffix ON PURPOSE: that was the
  // false positive the old `endsWith` guard carried, measured as main running —
  // and throwing — as a side effect of somebody else's import.
  const dir = join(BASE, 'importer');
  mkdirSync(dir, { recursive: true });
  cpSync(SCRIPT, join(dir, 'notify-failure.mjs'));
  const sibling = join(dir, 'security-notify-failure.mjs');
  writeFileSync(
    sibling,
    "import { decide } from './notify-failure.mjs';\nconsole.log('imported-ok', typeof decide);\n",
  );
  const r = spawnSync(process.execPath, [sibling], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '' },
  });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /imported-ok function/);
  assert.doesNotMatch(r.stderr, /GITHUB_TOKEN is required/);
});
