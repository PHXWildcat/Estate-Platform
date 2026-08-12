/**
 * THE CAP'S COVERAGE, AS A FENCE (M16 review).
 *
 * `SECOND_FACTOR_FAILURES` is a LIST, and the defect it was written to close is
 * what happens when a list goes stale: the cap counted `stepup.denied` alone
 * while `POST /v1/auth/totp/verify` checked the same `mfa_methods` row with no
 * cap at all, so forty wrong codes there produced forty 401s, never a 429, and
 * left the counter at zero — after which the code the guessing found elevated
 * at `stepup` on the first try. That was invisible because nothing related the
 * SET to the routes that write into it.
 *
 * So this reads `auth.service.ts` and asserts the relationship directly: every
 * ledger kind the service writes that MEANS "somebody submitted a wrong code"
 * must be counted, and every kind it counts must actually be written. A third
 * route that checks the factor arrives declared or turns this red.
 *
 * It is a SOURCE SCAN because there is nowhere else for it to live: `kind` is a
 * plain string at the repo boundary, so there is no union to exhaust, and a
 * runtime test could only observe the kinds the cases it happens to drive
 * produce. The vault-crypto zero-dependency fence is the precedent — read the
 * file, do not import the service.
 *
 * ANTI-VACUITY IS THE FIRST CASE, because a scan that stops matching goes green
 * (2026-08-07, and again in this very review).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SECOND_FACTOR_FAILURES, SECOND_FACTOR_SUCCESSES } from '../src/stepup';

const SERVICE = join(__dirname, '..', 'src', 'auth.service.ts');

/** Every `kind: '…'` literal the service hands the ledger. */
function kindsWritten(): string[] {
  const source = readFileSync(SERVICE, 'utf8');
  return [...source.matchAll(/kind:\s*'([a-z0-9._]+)'/g)].map((m) => m[1] as string);
}

/**
 * A wrong code is submitted at exactly the routes that READ the factor, and
 * each records its own kind. Naming them here rather than deriving them is
 * deliberate: the derivation is the thing under test, so the expectation has to
 * come from somewhere a regex cannot also get wrong. Adding a route means
 * adding a line here AND to `SECOND_FACTOR_FAILURES`, and the pair is the
 * review.
 */
const MEANS_A_WRONG_CODE = ['stepup.denied', 'totp.verify_failed'];

/** A refusal BY the cap. Counting it would let the counter feed itself. */
const NOT_A_FAILURE = ['stepup.rate_limited'];

describe('the second-factor attempt cap covers every route that checks the secret', () => {
  it('finds the kinds it is meant to be checking', () => {
    const written = kindsWritten();
    // The floor: the scan has found a real ledger surface, not an empty match.
    expect(written.length).toBeGreaterThanOrEqual(8);
    for (const kind of [...MEANS_A_WRONG_CODE, ...NOT_A_FAILURE]) {
      expect(written).toContain(kind);
    }
  });

  it('COUNTS every kind that means a wrong code was submitted', () => {
    for (const kind of MEANS_A_WRONG_CODE) {
      expect(SECOND_FACTOR_FAILURES as readonly string[]).toContain(kind);
    }
  });

  it('counts NOTHING ELSE — a kind that is not a wrong code must not be in the set', () => {
    // The counter must not be able to feed itself, and a broad predicate
    // (`kind LIKE 'stepup.%'`) is the way that happens.
    for (const kind of NOT_A_FAILURE) {
      expect(SECOND_FACTOR_FAILURES as readonly string[]).not.toContain(kind);
    }
    expect([...SECOND_FACTOR_FAILURES].sort()).toEqual([...MEANS_A_WRONG_CODE].sort());
  });

  it('every counted kind is one the service actually writes', () => {
    // The other direction: a kind left in the set after its route is deleted is
    // dead weight that reads as coverage.
    const written = new Set(kindsWritten());
    for (const kind of [...SECOND_FACTOR_FAILURES, ...SECOND_FACTOR_SUCCESSES]) {
      expect({ kind, written: written.has(kind) }).toEqual({ kind, written: true });
    }
  });

  it('every route that reads the factor passes the gate first', () => {
    // The set being right buys nothing if a route skips the check. Both callers
    // of `checkTotp` must be preceded by the gate — asserted on the source
    // because the alternative is trusting that a test happened to drive both.
    const source = readFileSync(SERVICE, 'utf8');
    const readers = [...source.matchAll(/await this\.checkTotp\(/g)];
    expect(readers.length).toBe(2);
    const gates = [...source.matchAll(/await this\.assertFactorAttemptsAvailable\(/g)];
    expect(gates.length).toBe(2);
    // …and each gate precedes a reader, rather than both sitting in one method.
    for (const reader of readers) {
      const before = source.slice(0, reader.index);
      const lastGate = before.lastIndexOf('assertFactorAttemptsAvailable(');
      const lastMethodStart = before.lastIndexOf('\n  async ');
      expect(lastGate).toBeGreaterThan(lastMethodStart);
    }
  });
});
