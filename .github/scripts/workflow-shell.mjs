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
 * TWO RULES, AND THE NARROW ONE IS NOT THE LOAD-BEARING ONE. The first keys on
 * a `'` that closes a single-quoted string and is immediately followed by a
 * WORD character — exactly `console's`, where the quote shuts at `console` and
 * `s` runs on. This header used to justify that by asserting a deliberate close
 * is followed by whitespace, `)`, `;`, `|`, `&`, or another quote. THAT IS A
 * CLAIM ABOUT ENGLISH AND IT IS FALSE: a possessive plural ends with an
 * apostrophe and a SPACE, so `the gates' numbers` closes the string just as
 * thoroughly and the narrow rule never sees it.
 *
 * So the load-bearing rule is STRUCTURAL and does not read the prose at all.
 * Every embedded script here has one shape — the opening quote is the last
 * thing on its line, the closing quote the first thing on its — so a body that
 * opens at end-of-line and closes anywhere else was cut short, by an
 * apostrophe, a stray quote or anything else, at any parity. `shortBodies`
 * applies it to single- AND double-quoted bodies; a `node -e "..."` needs no
 * apostrophe to be cut short by prose scare quotes, and had no rule of any kind
 * until it was measured. The escape dance `'"'"'` is exempt because its close
 * is followed by another quote: the shell is CONCATENATING, not ending the
 * body, and a fence must flag what is broken rather than what is merely ugly.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. This is not a shell parser. It tracks the
 * states that decide whether a quote is open at the end of a script (bare,
 * single-quoted, double-quoted, plus backslash escapes where they apply). A full
 * parse would be a much larger thing to trust, and quoting is the failure that
 * silently unhooks a gate.
 *
 * KNOWN LIMITATION, stated rather than left to be met as a mystery: a HEREDOC
 * body is shell input, not a shell string, so bash does not parse quotes inside
 * one — but this scanner does, and would read `don't` in a `<<'EOF'` block as an
 * unterminated quote. No workflow in this repo uses a heredoc today (measured),
 * so it is latent rather than live. Whoever adds the first one will get a red
 * finding that is the scanner's fault and not theirs; the fix at that point is
 * to skip heredoc bodies, not to widen the rule or to add an exemption.
 *
 * REFUSES WHAT IT CANNOT READ. A `run:` written in a shape the extractor does
 * not recognise is an ERROR naming the file and line, never a skip — a scan
 * that quietly matches nothing goes green for the same reason it is wrong.
 * THAT SENTENCE WAS FALSE IN SIX WAYS when it was written, and each was a
 * `run` key dropped on the floor: `run :` with a space before the colon, a
 * quoted `"run":` key, a flow mapping `- {run: ...}`, a plain scalar folded
 * across lines (truncated to its first line), `defaults.run` (a MAPPING, read
 * as a script), and the double-quoted body above. Every line that looks like a
 * run key is counted in `seen` now, and `seen === scripts + refusals` is an
 * invariant the sweep reports PER FILE — because a global floor cannot see one
 * workflow going blank while the others satisfy it, which is what made all six
 * silent rather than loud.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** `run:` values that introduce a YAML block scalar. */
// A `run` KEY in any spelling a YAML parser would accept: canonical, a space
// before the colon, a quoted key, or the first key of a flow mapping.
// DELIBERATELY OVER-EAGER — its only job is to notice that a line is ABOUT a
// run key, so an unrecognised spelling becomes a refusal instead of vanishing.
const RUN_KEY_ANYWHERE = /(?:^|[\s{,])(["']?)run\1\s*:/;

// The one spelling this module reads: `run:` at the start of a line, optionally
// as the first key of a sequence item.
const RUN_KEY_CANONICAL = /^(\s*)(?:-\s+)?run:(.*)$/;

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
  // Every RUN_KEY_ANYWHERE match must leave as a script or a refusal. `seen`
  // is what makes that checkable rather than asserted.
  let seen = 0;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    // A `run:` KEY, not the word appearing inside someone's script. Anchored on
    // the indentation so a `run:` nested inside a block scalar (which is script
    // text, already covered by its own block) is not re-extracted.
    const m = RUN_KEY_CANONICAL.exec(line);
    if (!m) {
      // SEEN BUT NOT READ IS A REFUSAL, NEVER A SKIP. `run :` with a space
      // before the colon, `"run":` with a quoted key, and a flow mapping
      // `- {run: ...}` are all valid YAML that the canonical regex rejects.
      // Before this, each of them vanished: no script, no refusal, and a
      // defect inside one invisible to a fence reporting zero findings.
      if (RUN_KEY_ANYWHERE.test(line)) {
        seen += 1;
        unreadable.push({
          line: i + 1,
          reason: `a \`run\` key in a spelling this module cannot read: ${JSON.stringify(line.trim())}`,
        });
      }
      continue;
    }
    seen += 1;

    const indent = m[1].length + (/^\s*-\s+/.test(line) ? 2 : 0);
    const rest = m[2].trim();

    // `defaults.run` is a MAPPING (`shell:`, `working-directory:`), not a
    // script. Reading it as one scans YAML as shell and inflates the block
    // count with a non-script, so the floor rises while coverage does not.
    // No workflow here uses it; refusing keeps it visible if one starts.
    if (parentKeyOf(lines, i, indent) === 'defaults') {
      unreadable.push({
        line: i + 1,
        reason: '`defaults.run` is a mapping of shell settings, not a script',
      });
      continue;
    }

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
      // (No refusal here: the enclosing condition already guarantees `rest`
      // is either empty or a header BLOCK accepts. A branch that cannot fire
      // is a branch nobody has read.)
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
    // A PLAIN SCALAR MAY FOLD ACROSS LINES. `run: echo one` followed by a
    // deeper-indented line is one YAML string, and taking only the first line
    // silently drops the rest — a defect on a continuation line disappears
    // while the block still counts toward the floor.
    const cont = lines[i + 1];
    if (
      cont !== undefined &&
      cont.trim() !== '' &&
      cont.length - cont.trimStart().length > indent
    ) {
      unreadable.push({
        line: i + 1,
        reason: 'a plain scalar folded across lines — cannot judge its shell without folding it',
      });
      continue;
    }
    scripts.push({ line: i + 1, bodyLine: i + 1, body: rest });
  }

  return { scripts, unreadable, seen };
}

/**
 * The key one level above `lines[i]`, or null. Used only to tell a step's
 * `run:` (a script) from `defaults.run` (a mapping of shell settings).
 */
function parentKeyOf(lines, i, indent) {
  for (let j = i - 1; j >= 0; j -= 1) {
    const l = lines[j];
    if (l.trim() === '' || /^\s*#/.test(l)) continue;
    if (l.length - l.trimStart().length < indent) {
      const k = /^\s*([A-Za-z_][\w-]*)\s*:/.exec(l);
      return k ? k[1] : null;
    }
  }
  return null;
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
  const regions = [];
  let openAtEol = false;

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
        regions.push({
          kind: 'single',
          line: openedAt.line,
          column: openedAt.column,
          closeLine: line,
          openAtEol,
          // The first non-whitespace on its line? `slice` back to the newline.
          closeAtBol: /^\s*$/.test(script.slice(script.lastIndexOf('\n', i - 1) + 1, i)),
          // Shell CONCATENATION: `'...'"'"'...'` is the only way to write an
          // apostrophe inside single quotes, and its close is immediately
          // followed by another quote. The string is being joined, not ended,
          // so the body has not been cut short. A fence must flag what is
          // broken, not what is merely ugly.
          concatenated: script[i + 1] === '"' || script[i + 1] === "'",
        });
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
        // A backslash-escaped NEWLINE still ends a line. Skipping it without
        // counting it reported every later finding N lines early.
        if (script[i + 1] === '\n') {
          line += 1;
          column = 0;
        } else {
          column += 1;
        }
        i += 1;
        continue;
      }
      if (ch === '"') {
        state = 'bare';
        // A DOUBLE-quoted body is cut short the same way a single-quoted one
        // is — by prose. `node -e "... the \"exact\" count ..."` needs no
        // apostrophe at all, and before this it had no rule of any kind.
        regions.push({
          kind: 'double',
          line: openedAt.line,
          column: openedAt.column,
          closeLine: line,
          openAtEol,
          closeAtBol: /^\s*$/.test(script.slice(script.lastIndexOf('\n', i - 1) + 1, i)),
          concatenated: script[i + 1] === '"' || script[i + 1] === "'",
        });
      }
      continue;
    }

    if (ch === '\\') {
      if (script[i + 1] === '\n') {
        line += 1;
        column = 0;
      } else {
        column += 1;
      }
      i += 1;
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
      // Last non-whitespace on its line? Then this opens a multi-line body.
      const eol = script.indexOf('\n', i + 1);
      openAtEol = eol !== -1 && /^\s*$/.test(script.slice(i + 1, eol));
      continue;
    }
    if (ch === '"') {
      state = 'double';
      openedAt = { line, column };
      const eolD = script.indexOf('\n', i + 1);
      openAtEol = eolD !== -1 && /^\s*$/.test(script.slice(i + 1, eolD));
    }
  }

  return {
    unterminated: state === 'bare' ? null : { kind: state, ...openedAt },
    accidental,
    regions,
  };
}

/**
 * A multi-line single-quoted body must close on a line of its own.
 *
 * THIS IS THE STRUCTURAL CHECK, and it is the one that actually covers the
 * class. The accidental-close rule above keys on `'` followed by a word
 * character, which catches `console's` and MISSES `the gates' numbers` — a
 * possessive plural closes the string just as thoroughly and is followed by a
 * space. Measured: two of those in one prose comment re-balance the quotes,
 * bash splits the body, node evaluates a valid prefix, and the step exits 0
 * with the assertion gone. Same silent-green failure, one rule over.
 *
 * Every embedded script in this repo has the same shape — the opening quote is
 * the LAST thing on its line and the closing quote is the FIRST thing on its:
 *
 *     node -e '
 *       ...body...
 *     '
 *
 * So a region that opens at end-of-line and closes anywhere but at the start of
 * a line has been cut short by something in the body, whatever that something
 * looks like and whatever the apostrophe count is. That is a property of the
 * SHAPE rather than of the prose, which is why it does not need to guess.
 */
export function shortBodies(script) {
  return scanQuoting(script).regions.filter((r) => r.openAtEol && !r.closeAtBol && !r.concatenated);
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
  // PER FILE, because a global count cannot see a file the extractor read
  // NOTHING from. That is what made every miss above silent instead of loud:
  // one workflow going blank is invisible under a total that 46 other blocks
  // already satisfy. An anti-vacuity check belongs on every LEVEL of a scan.
  const perFile = [];
  let blocks = 0;

  for (const file of workflowFiles(dir)) {
    const { scripts, unreadable, seen } = extractRunBlocks(readFileSync(file.path, 'utf8'));
    perFile.push({
      file: file.name,
      seen,
      scripts: scripts.length,
      refusals: unreadable.length,
      // THE INVARIANT: every line that looked like a run key left as one or
      // the other. False here means the extractor dropped one on the floor.
      accounted: seen === scripts.length + unreadable.length,
    });
    for (const r of unreadable) refusals.push({ file: file.name, ...r });
    for (const script of scripts) {
      blocks += 1;
      const { unterminated: open, accidental } = scanQuoting(script.body);
      for (const r of shortBodies(script.body)) {
        findings.push({
          file: file.name,
          line: script.bodyLine + r.line - 1,
          column: r.column,
          kind: 'body-cut-short',
          detail: `a multi-line ${r.kind}-quoted body opened here closes mid-line on line ${script.bodyLine + r.closeLine - 1} — something in the body ended it early`,
        });
      }
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

  return { findings, refusals, blocks, perFile };
}
