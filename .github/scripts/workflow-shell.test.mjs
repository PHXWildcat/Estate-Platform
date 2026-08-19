/**
 * Tests for the workflow quoting fence.
 *
 * The case that matters most is `THE REPO ITSELF`, at the bottom: it is the
 * only one that can catch a real defect, and it is the one that would go green
 * for the wrong reason if the extractor ever stopped reading `run:` blocks. So
 * it carries an anti-vacuity floor on the number of blocks scanned and requires
 * the refusal list to be EMPTY — a workflow written in a shape the extractor
 * cannot read must fail the fence rather than be skipped by it.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { extractRunBlocks, sweep, unterminatedQuote, workflowFiles } from './workflow-shell.mjs';

const WORKFLOWS = join(dirname(fileURLToPath(import.meta.url)), '..', 'workflows');

test('THE HISTORICAL DEFECT — an apostrophe in prose inside a single-quoted body', () => {
  // Reduced from images.yml as it stood on 2026-08-19. Nothing escapes inside
  // single quotes, so `console's` closes the string and the terminator below
  // opens one that never closes.
  const script = [
    "node -e '",
    '  const r = require("./stack-results.json");',
    "  // M21 PR3b added the console's settlement round trip: 32/4 -> 33/4.",
    '  if (r.numPassedTests !== 33) process.exit(1);',
    "'",
  ].join('\n');

  const open = unterminatedQuote(script);
  assert.ok(open, 'the fence must see the apostrophe defect');
  assert.equal(open.kind, 'single');
  assert.equal(
    open.line,
    5,
    'it is the TERMINATOR that is left open, once prose closed the string early',
  );
});

test('the same body without the apostrophe is clean', () => {
  const script = [
    "node -e '",
    '  // M21 PR3b added the operator console settlement round trip.',
    '  if (r.numPassedTests !== 33) process.exit(1);',
    "'",
  ].join('\n');
  assert.equal(unterminatedQuote(script), null);
});

test('an apostrophe inside DOUBLE quotes is fine — the naive check is wrong here', () => {
  assert.equal(unterminatedQuote('echo "don\'t"'), null);
});

test('an ESCAPED apostrophe outside quotes is fine', () => {
  assert.equal(unterminatedQuote("echo don\\'t"), null);
});

test('an apostrophe in a SHELL COMMENT is inert', () => {
  // Without this, every `# don't` in the repo is a false positive, and a fence
  // that cries wolf is one whose next real finding is ignored.
  assert.equal(unterminatedQuote("# don't do this\necho ok"), null);
  // ...but a `#` INSIDE a quoted string is not a comment.
  assert.ok(unterminatedQuote("echo 'a # b"));
});

test('quotes legitimately spanning many lines are not flagged', () => {
  assert.equal(unterminatedQuote("node -e '\n  one\n  two\n'"), null);
});

test('an unterminated DOUBLE quote is caught too', () => {
  const open = unterminatedQuote('echo "oops');
  assert.equal(open?.kind, 'double');
});

test('a backslash inside double quotes escapes, inside single quotes it does not', () => {
  assert.equal(unterminatedQuote('echo "a\\"b"'), null);
  // In single quotes a backslash is literal, so this closes at the second quote
  // and the third opens an unterminated one.
  assert.ok(unterminatedQuote("echo 'a\\'b'"));
});

test('EXTRACTION reads block scalars and single-line runs, and reports where each body starts', () => {
  const yaml = [
    'jobs:',
    '  a:',
    '    steps:',
    '      - name: block',
    '        run: |',
    '          echo one',
    '          echo two',
    '      - name: inline',
    '        run: echo three',
  ].join('\n');

  const { scripts, unreadable } = extractRunBlocks(yaml);
  assert.deepEqual(unreadable, []);
  assert.equal(scripts.length, 2);
  assert.match(scripts[0].body, /echo one/);
  assert.match(scripts[0].body, /echo two/);
  // The block's body starts on the line AFTER the key; the inline body is ON it.
  assert.equal(scripts[0].bodyLine, 6);
  assert.equal(scripts[1].bodyLine, 9);
  assert.equal(scripts[1].body, 'echo three');
});

test('a block scalar ENDS at the next key, so a later step is not swallowed', () => {
  const yaml = [
    '      - name: one',
    '        run: |',
    '          echo body',
    '      - name: two',
    '        run: echo other',
  ].join('\n');
  const { scripts } = extractRunBlocks(yaml);
  assert.equal(scripts.length, 2);
  assert.doesNotMatch(scripts[0].body, /other/);
});

test('REFUSES a quoted YAML scalar rather than guessing at its shell', () => {
  const { scripts, unreadable } = extractRunBlocks('        run: "echo hi"');
  assert.equal(scripts.length, 0);
  assert.equal(unreadable.length, 1);
  assert.match(unreadable[0].reason, /quoted YAML scalar/);
});

test('the word `run:` inside a script body is not mistaken for a key', () => {
  const yaml = ['        run: |', '          echo "how to run: this"'].join('\n');
  const { scripts } = extractRunBlocks(yaml);
  assert.equal(scripts.length, 1);
});

test('THE REPO ITSELF — every run block in every workflow closes its quotes', () => {
  const files = workflowFiles(WORKFLOWS);
  const { findings, refusals, blocks } = sweep(WORKFLOWS);

  // ANTI-VACUITY. A broken extractor scans nothing and passes perfectly; these
  // floors are what turn that into a failure. They are deliberately well under
  // the real numbers so ordinary additions do not trip them.
  assert.ok(files.length >= 5, `expected to find the workflows, saw ${files.length}`);
  assert.ok(blocks >= 30, `expected to scan the run blocks, saw ${blocks}`);

  // A shape the extractor cannot read is a FAILURE, not a skip.
  assert.deepEqual(
    refusals,
    [],
    'a run: block could not be read — teach the extractor, do not skip it',
  );

  assert.deepEqual(
    findings.map((f) => `${f.file}:${f.line}:${f.column} unterminated ${f.kind} quote`),
    [],
  );
});
