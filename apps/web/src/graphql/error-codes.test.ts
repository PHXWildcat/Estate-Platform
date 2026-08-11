import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { GQL_ERROR_CODES } from './client';
import { errorCopy } from '../lib/copy';

/**
 * `GQL_ERROR_CODES` IS A SECOND COPY OF THE BFF'S `BffErrorCode`, and until this
 * file nothing checked it.
 *
 * The two lists have to agree for a very specific reason. `extractErrorCode`
 * narrows an untrusted payload against this list and anything unrecognised
 * becomes `UNKNOWN`, whose copy is "something went wrong on our side" — so a
 * code the BFF adds and this app does not learn DEGRADES A CONTROL FIRING INTO
 * AN OUTAGE. That is the exact inversion M9 wrote down ("a control firing must
 * not read as an outage") and M12 restated with three upload refusals that mean
 * three different things to the person holding the file. The failure is
 * silent: every test on both sides passes, because each list is internally
 * consistent.
 *
 * READ THE FILE, DO NOT IMPORT IT — the compose-parity mechanism (M8) and the
 * one `step-up.test.ts` already uses to pin a number to auth-guard's. This app
 * cannot import from `apps/bff`: it is a separate workspace package with a Nest
 * dependency tree, and adding that edge to ship one union would be a far larger
 * change than the drift it prevents.
 *
 * Parsed, never evaluated. The union is a sequence of `| 'CODE'` lines, and the
 * ANTI-VACUITY FLOOR below is not decoration: the M14 review found a
 * credential-graph scan that had silently stopped matching anything and gone
 * green for a whole milestone, so a scan whose regex stops fitting must fail
 * rather than pass over an empty set.
 */
const IDENTITY_CLIENT = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'apps',
  'bff',
  'src',
  'identity-client.ts',
);

function declaredBffErrorCodes(): string[] {
  const source = readFileSync(IDENTITY_CLIENT, 'utf8');
  const start = source.indexOf('export type BffErrorCode =');
  expect(start).toBeGreaterThanOrEqual(0);
  // ANCHORED AT BOTH ENDS. The M15 review found a fence anchored at one end
  // scanning the whole file and still going green under mutation, because a
  // scan that is too WIDE catches the planted defect and hides that it is not
  // testing the stated layer. The terminator is the LAST MEMBER's own `';`
  // rather than the first `;` after the declaration: the members carry doc
  // comments, and one of them has a semicolon in its prose, which cut the union
  // off at nine codes when this was first written — caught only by the
  // anti-vacuity floor below, which is the argument for having one.
  const terminator = /'[A-Z_]+';/.exec(source.slice(start));
  expect(terminator).not.toBeNull();
  const { index, 0: matched } = terminator as RegExpExecArray;
  const declaration = source.slice(start, start + index + matched.length);
  return [...declaration.matchAll(/\|\s*'([A-Z_]+)'/g)].map(([, code]) => code as string);
}

describe('the BFF error-code union and this app’s copy of it', () => {
  it('agrees code for code, in both directions', () => {
    const declared = declaredBffErrorCodes();

    // ANTI-VACUITY. Without this the whole suite passes if the regex ever stops
    // matching — which is how the union could be emptied and every assertion
    // below become true of nothing.
    expect(declared.length).toBeGreaterThanOrEqual(20);
    expect(declared).toContain('UNAUTHENTICATED');
    expect(declared).toContain('STEPUP_REQUIRED');

    // EQUALITY, not containment. A code the BFF adds and this app misses turns
    // a refusal into UNKNOWN; a code this app keeps and the BFF has dropped is
    // dead copy nobody will ever see, and the next reader has no way to tell
    // which of the two it is.
    expect([...GQL_ERROR_CODES].sort()).toEqual([...declared].sort());
  });

  it('gives every code its own sentence — no code falls through to a generic apology', () => {
    for (const code of GQL_ERROR_CODES) {
      expect(typeof errorCopy[code]).toBe('string');
      expect(errorCopy[code].length).toBeGreaterThan(0);
      // Distinct from the generic one. `errorCopy` is a total Record so a
      // missing entry is a compile error, but nothing stops a new code being
      // wired to the same sentence as UNKNOWN, which is the same failure
      // wearing a different hat.
      expect(errorCopy[code]).not.toBe(errorCopy.UNKNOWN);
    }
  });
});
