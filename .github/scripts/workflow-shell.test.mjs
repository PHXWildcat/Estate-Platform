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

import {
  extractRunBlocks,
  scanQuoting,
  shortBodies,
  sweep,
  unterminatedQuote,
  workflowFiles,
} from './workflow-shell.mjs';

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

test('THE SILENT HALF — an EVEN number of prose apostrophes re-balances the quotes', () => {
  // This is the dangerous one and an unterminated-quote check cannot see it.
  // MEASURED with bash: the body below splits into THREE arguments, node
  // evaluates only the first (`const r = 1; // its`, which is valid
  // JavaScript), exits 0, and the assertion is simply gone. The step passes.
  const q = String.fromCharCode(39);
  const script = [
    `node -e ${q}`,
    '  const r = 1;',
    `  // it${q}s the console${q}s round trip`,
    '  console.log("RAN");',
    q,
  ].join('\n');

  const { unterminated, accidental } = scanQuoting(script);
  assert.equal(unterminated, null, 'the quotes DO balance — that is what makes it silent');
  assert.equal(accidental.length, 1, 'and the accidental close is what catches it anyway');
  assert.equal(accidental[0].line, 3);
  assert.equal(accidental[0].after, 's');
});

test('THE EVASION THE WORD-CHARACTER RULE MISSES — a possessive PLURAL', () => {
  // `console's` closes the string and is followed by `s`, so the accidental
  // rule sees it. `the gates' numbers` closes it just as thoroughly and is
  // followed by a SPACE. Two of them re-balance the quotes, so neither the
  // unterminated check nor the accidental check fires — MEASURED: bash exits 0
  // and the assertion never runs. The structural check is what covers it.
  const q = String.fromCharCode(39);
  const script = [
    `node -e ${q}`,
    '  const r = 1;',
    `  // the gates${q} numbers and the twins${q} numbers must agree.`,
    '  console.log("RAN");',
    q,
  ].join('\n');

  const { unterminated, accidental } = scanQuoting(script);
  assert.equal(unterminated, null, 'balanced, so the unterminated check is blind');
  assert.deepEqual(accidental, [], 'followed by a space, so the word-character rule is blind too');
  assert.equal(shortBodies(script).length, 1, 'the structural check is what sees it');
});

test('THE STRUCTURAL CHECK — a body that opens at end-of-line must close at start-of-line', () => {
  const q = String.fromCharCode(39);
  const good = [`node -e ${q}`, '  console.log("ok");', q].join('\n');
  assert.deepEqual(shortBodies(good), [], 'the shape every embedded script in this repo has');

  // Cut short by anything at all, not just an apostrophe in prose.
  const cut = [`node -e ${q}`, `  console.log("ok");${q} echo surprise`, ''].join('\n');
  assert.equal(shortBodies(cut).length, 1);
});

test('a SINGLE-LINE quoted argument is not a multi-line body', () => {
  // The structural rule must not fire on ordinary quoting, or it is noise.
  assert.deepEqual(shortBodies("echo 'hello' && echo 'world'"), []);
  assert.deepEqual(shortBodies("awk '/^# pass /{print $3}' file"), []);
});

test('the ESCAPE DANCE is not a false positive', () => {
  // `'"'"'` is the only way to write an apostrophe inside single quotes, and
  // stack.yml used it for years. Its close is followed by `"`, not by a word
  // character, so the rule is on the cause rather than on the count.
  const q = String.fromCharCode(39);
  const script = [`node -e ${q}`, `  // profile${q}"${q}"${q}s block`, q].join('\n');
  assert.deepEqual(scanQuoting(script).accidental, []);
  // ...and the STRUCTURAL check must exempt it too: its close is followed by a
  // quote, so the shell is concatenating rather than ending the body. Without
  // this assertion the concatenation exemption has no test at all.
  assert.deepEqual(shortBodies(script), []);
});

test('a deliberate close followed by punctuation or space is not flagged', () => {
  for (const script of ["echo 'a' 'b'", "echo 'a';", "echo 'a')", "grep 'x' | wc -l", "echo 'a'"]) {
    assert.deepEqual(scanQuoting(script).accidental, [], script);
  }
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

test('KNOWN LIMITATION: a heredoc body is scanned as if it were shell', () => {
  // Recorded, not fixed. Bash does not parse quotes inside a heredoc, so this
  // is a false positive — and no workflow in the repo has one, so it is latent.
  // The test exists so the behaviour is a documented decision rather than a
  // surprise, and so that whoever fixes it has a case to flip.
  const q = String.fromCharCode(39);
  const script = ['cat > f <<' + q + 'EOF' + q, "don't worry", 'EOF'].join('\n');
  assert.ok(unterminatedQuote(script), 'today it flags this; fix by skipping heredoc bodies');
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

test('THE REPO ITSELF — every embedded body is delimited the way its author meant', () => {
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
