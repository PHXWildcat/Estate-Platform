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
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
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
