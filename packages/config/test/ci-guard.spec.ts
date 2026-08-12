/**
 * THE GUARD'S OWN TESTS, which the eleven copies never had.
 *
 * Unifying them trades blast radius for drift: one careless edit here now
 * weakens eleven gates at once, where before it could only weaken one. This
 * file is the price of that trade, and it is only worth paying if it actually
 * refuses everything the copies refused — so every case below is a
 * CONFIGURATION THAT MUST FAIL, driven over a fabricated environment rather
 * than over whatever the runner happens to have.
 *
 * `evaluate` is pure for exactly this reason. A guard that could only be
 * exercised by setting real environment variables in a real CI run is one
 * whose failure modes are discovered in production, which is the situation
 * that produced it.
 */
import { evaluate, type CiGuardOptions } from '../ci-guard';

/** Did every assertion this environment produces hold? */
function passes(env: Record<string, string | undefined>, options?: CiGuardOptions): boolean {
  return evaluate(env, options).every((r) => r.satisfied);
}

const STACK_RULE = {
  when: 'CI_REQUIRE_STACK',
  requires: 'STACK_TEST',
  why: 'the stack e2e suites skip green without it',
} as const;

describe('the guard every package shares', () => {
  it('is SILENT outside CI, where no database is promised', () => {
    // The local case. A developer with no Postgres must not be failed by it.
    expect(passes({})).toBe(true);
    expect(passes({ PG_TEST_URL: '' })).toBe(true);
  });

  it('FAILS in CI with no database — the whole reason it exists', () => {
    expect(passes({ CI: 'true' })).toBe(false);
    expect(passes({ CI: 'true', PG_TEST_URL: '' })).toBe(false);
  });

  it('passes in CI with a database', () => {
    expect(passes({ CI: 'true', PG_TEST_URL: 'postgres://x/y' })).toBe(true);
  });

  it('registers exactly one assertion by default', () => {
    // Anti-vacuity: an options shape that quietly registered nothing would be a
    // spec file that asserts nothing while reading like a gate.
    expect(evaluate({ CI: 'true', PG_TEST_URL: 'x' })).toHaveLength(1);
  });
});

describe('the declared database-free run (identity)', () => {
  const options: CiGuardOptions = { databaseFreeRunFlag: 'IDENTITY_NO_DB_RUN' };

  it('admits a CI run with no database WHEN it declares itself', () => {
    expect(passes({ CI: 'true', IDENTITY_NO_DB_RUN: '1' }, options)).toBe(true);
    expect(passes({ CI: 'true', IDENTITY_NO_DB_RUN: '1', PG_TEST_URL: '' }, options)).toBe(true);
  });

  it('STILL FAILS a CI run with no database and no declaration', () => {
    // The original guard, intact for the package that also has the exemption.
    expect(passes({ CI: 'true' }, options)).toBe(false);
  });

  it('IS NOT A MUTE BUTTON: declaring it beside a live database fails', () => {
    // The property that stops the flag being pasted into the ordinary test step
    // to silence the guard — it would fail the other direction instead.
    expect(
      passes({ CI: 'true', IDENTITY_NO_DB_RUN: '1', PG_TEST_URL: 'postgres://x/y' }, options),
    ).toBe(false);
  });

  it('only `1` declares it — a truthy-looking value is not a declaration', () => {
    // `true`, `yes` or an accidental empty-string-to-`0` must not exempt
    // anything, or the flag becomes whatever a shell happened to export.
    for (const value of ['true', 'yes', '0', '']) {
      expect(passes({ CI: 'true', IDENTITY_NO_DB_RUN: value }, options)).toBe(false);
    }
  });

  it('registers the second assertion only where the flag is configured', () => {
    expect(evaluate({ CI: 'true', PG_TEST_URL: 'x' }, options)).toHaveLength(2);
    expect(evaluate({ CI: 'true', PG_TEST_URL: 'x' })).toHaveLength(1);
  });
});

describe('extra promise/gate pairs (the e2e stack gate)', () => {
  const options: CiGuardOptions = { alsoRequires: [STACK_RULE] };

  it('FAILS when the workflow promises the stack and the gate is unset', () => {
    expect(
      passes({ CI: 'true', PG_TEST_URL: 'postgres://x/y', CI_REQUIRE_STACK: '1' }, options),
    ).toBe(false);
  });

  it('passes when the promised gate is armed', () => {
    expect(
      passes(
        { CI: 'true', PG_TEST_URL: 'postgres://x/y', CI_REQUIRE_STACK: '1', STACK_TEST: '1' },
        options,
      ),
    ).toBe(true);
  });

  it('is silent when the workflow makes no such promise', () => {
    expect(passes({ CI: 'true', PG_TEST_URL: 'postgres://x/y' }, options)).toBe(true);
  });

  it('keeps the database rule independent of the extra pair', () => {
    // Arming the stack gate must not excuse a missing database.
    expect(passes({ CI: 'true', CI_REQUIRE_STACK: '1', STACK_TEST: '1' }, options)).toBe(false);
  });

  it('names what skips, so a failure says what was lost', () => {
    const [, stack] = evaluate({ CI: 'true' }, options);
    expect(stack?.name).toContain('STACK_TEST');
    expect(stack?.name).toContain(STACK_RULE.why);
  });
});
