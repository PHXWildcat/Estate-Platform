/**
 * A parse of every `run:` block in every workflow, and a quoting check over it.
 *
 * WHY THIS EXISTS. On 2026-08-19 a prose comment inside an inline
 * `node -e '...'` gained the word `console's`. The apostrophe CLOSED the
 * single-quoted shell string; bash parsed the remainder as shell, found a
 * redirection, and never executed node — so an exact-count gate silently
 * stopped running. It surfaced as a confusing shell error rather than as a
 * failed assertion, and it had been inert for every run since it landed.
 *
 * A GREP CANNOT SEE THIS. `grep "'"` matches every workflow in the repo, and
 * counting apostrophes per line is wrong in both directions: `"don't"` inside
 * double quotes is fine, and a quote opened on one line legitimately closes
 * many lines later. The property is a property of the WHOLE run body, and
 * answering it means tracking shell quoting state across it — which is a parse.
 *
 * IT CATCHES BOTH HALVES, and the second is the dangerous one. An ODD number of
 * stray apostrophes leaves a quote UNTERMINATED, which is the failure above: it
 * fails loudly. An EVEN number RE-BALANCES them, and that one is silent-green.
 * Measured, with `// it's the console's round trip` inside a `node -e` body:
 * bash splits it into THREE arguments, node evaluates only the first —
 * `const r = {...}; // its`, which is valid JavaScript — exits 0, and the
 * assertion has simply vanished. The step passes. So an unterminated-quote check
 * alone would have been blind to the worse half of the class it was written for.
 *
 * The second check is on the CAUSE rather than on the symptom, which is what
 * lets one rule cover both: a `'` that CLOSES a single-quoted string and is
 * immediately followed by a word character is an accidental close. That is
 * exactly `console's` — the quote shuts at `console` and `s` runs on. A
 * deliberate close is followed by whitespace, a newline, `)`, `;`, `|`, `&`, or
 * another quote — including `'"'"'`, the escape dance, whose close is followed
 * by `"`. It fires at the FIRST accidental close, so it does not care whether
 * the count is odd or even.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. This is not a shell parser. It tracks the
 * states that decide whether a quote is open at the end of a script (bare,
 * single-quoted, double-quoted, plus backslash escapes where they apply). A full
 * parse would be a much larger thing to trust, and quoting is the failure that
 * silently unhooks a gate.
 *
 * REFUSES WHAT IT CANNOT READ. A `run:` written in a shape the extractor does
 * not recognise is an ERROR naming the file and line, never a skip — a scan
 * that quietly matches nothing goes green for the same reason it is wrong.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** `run:` values that introduce a YAML block scalar. */
const BLOCK = /^[|>][+-]?\d*$|^\d*[+-]?$/;

/**
 * Extract every `run:` script from one workflow's source.
 *
 * Returns `{ scripts, unreadable }` — `unreadable` is the refusal list, and a
 * caller that ignores it has a fence that stops matching without saying so.
 */
export function extractRunBlocks(source) {
  const lines = source.split('\n');
  const scripts = [];
  const unreadable = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    // A `run:` KEY, not the word appearing inside someone's script. Anchored on
    // the indentation so a `run:` nested inside a block scalar (which is script
    // text, already covered by its own block) is not re-extracted.
    const m = /^(\s*)(?:-\s+)?run:(.*)$/.exec(line);
    if (!m) continue;

    const indent = m[1].length + (/^\s*-\s+/.test(line) ? 2 : 0);
    const rest = m[2].trim();

    if (rest === '' || BLOCK.test(rest)) {
      // Block scalar: every following line indented deeper than the key.
      const body = [];
      let j = i + 1;
      for (; j < lines.length; j += 1) {
        const next = lines[j];
        if (next.trim() === '') {
          body.push('');
          continue;
        }
        const nextIndent = next.length - next.trimStart().length;
        if (nextIndent <= indent) break;
        body.push(next);
      }
      if (rest !== '' && !BLOCK.test(rest)) {
        unreadable.push({
          line: i + 1,
          reason: `unrecognised block scalar header ${JSON.stringify(rest)}`,
        });
      }
      scripts.push({ line: i + 1, bodyLine: i + 2, body: body.join('\n') });
      i = j - 1;
      continue;
    }

    if (rest.startsWith('|') || rest.startsWith('>')) {
      unreadable.push({
        line: i + 1,
        reason: `unrecognised block scalar header ${JSON.stringify(rest)}`,
      });
      continue;
    }

    // A single-line `run: some command`. A quoted YAML scalar would need YAML
    // unescaping before its shell could be judged, so it is refused rather than
    // guessed at.
    if (rest.startsWith('"') || rest.startsWith("'")) {
      unreadable.push({
        line: i + 1,
        reason: 'quoted YAML scalar — cannot judge its shell without unescaping it',
      });
      continue;
    }
    scripts.push({ line: i + 1, bodyLine: i + 1, body: rest });
  }

  return { scripts, unreadable };
}

/**
 * Track shell quoting across a script and report an unterminated quote.
 *
 * Returns `null` when every quote closes, else `{ kind, line, column }` for the
 * quote that was left open — the OPENING position, which is what a person needs
 * in order to fix it, rather than the end of the file where it was noticed.
 */
export function scanQuoting(script) {
  let state = 'bare';
  let openedAt = null;
  let line = 1;
  let column = 0;
  const accidental = [];

  for (let i = 0; i < script.length; i += 1) {
    const ch = script[i];
    column += 1;
    if (ch === '\n') {
      line += 1;
      column = 0;
      // A newline inside a quote is legal and common; it does not reset state.
      continue;
    }

    if (state === 'single') {
      // Nothing escapes inside single quotes — not even a backslash. This is
      // the whole reason the defect exists: there is no way to write an
      // apostrophe here, so the first one always closes the string.
      if (ch === "'") {
        state = 'bare';
        // An accidental close: the shell shuts the string here and the rest of
        // the word runs on unquoted. `console's` is this exactly.
        if (/[A-Za-z0-9_]/.test(script[i + 1] ?? '')) {
          accidental.push({ line, column, after: script[i + 1] });
        }
      }
      continue;
    }

    if (state === 'double') {
      if (ch === '\\') {
        i += 1;
        column += 1;
        continue;
      }
      if (ch === '"') state = 'bare';
      continue;
    }

    if (ch === '\\') {
      i += 1;
      column += 1;
      continue;
    }
    if (ch === '#' && (i === 0 || /\s/.test(script[i - 1]))) {
      // A shell COMMENT runs to end of line and its apostrophes are inert.
      // Without this, every `# don't` in a run block is a false positive — and
      // a fence that cries wolf is one whose next real finding is ignored.
      while (i < script.length && script[i] !== '\n') i += 1;
      i -= 1;
      continue;
    }
    if (ch === "'") {
      state = 'single';
      openedAt = { line, column };
      continue;
    }
    if (ch === '"') {
      state = 'double';
      openedAt = { line, column };
    }
  }

  return {
    unterminated: state === 'bare' ? null : { kind: state, ...openedAt },
    accidental,
  };
}

/**
 * The unterminated half alone, kept as its own name because that is the failure
 * people describe when they hit it. One scanner underneath, so the two notions
 * cannot drift apart.
 */
export function unterminatedQuote(script) {
  return scanQuoting(script).unterminated;
}

/** Every workflow file, so a new one is covered without anyone remembering. */
export function workflowFiles(dir) {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))
    .sort()
    .map((f) => ({ name: f, path: join(dir, f) }));
}

/** The whole sweep: every workflow, every run block, every unterminated quote. */
export function sweep(dir) {
  const findings = [];
  const refusals = [];
  let blocks = 0;

  for (const file of workflowFiles(dir)) {
    const { scripts, unreadable } = extractRunBlocks(readFileSync(file.path, 'utf8'));
    for (const r of unreadable) refusals.push({ file: file.name, ...r });
    for (const script of scripts) {
      blocks += 1;
      const { unterminated: open, accidental } = scanQuoting(script.body);
      for (const a of accidental) {
        findings.push({
          file: file.name,
          line: script.bodyLine + a.line - 1,
          column: a.column,
          kind: 'accidental-close',
          detail: `a single-quoted string closes here and \`${a.after}\` runs on unquoted — an apostrophe in prose`,
        });
      }
      if (open) {
        findings.push({
          file: file.name,
          // The BODY's start line plus the offset within it. Those differ by
          // form — a block scalar's body begins on the line after the `run:`
          // key, a single-line `run:` body sits on it — and collapsing them
          // reported every block-scalar finding one line early. A fence that
          // mis-attributes still goes red, and still sends the reader to the
          // wrong line.
          line: script.bodyLine + open.line - 1,
          kind: open.kind,
          column: open.column,
        });
      }
    }
  }

  return { findings, refusals, blocks };
}
