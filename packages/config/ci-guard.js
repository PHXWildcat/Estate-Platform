'use strict';

/**
 * THE CI INTEGRATION-TEST GUARD, in one place.
 *
 * Gated suites skip when their environment is absent — fine locally, where the
 * dependency may not exist — but where CI PROMISES the environment, a missing
 * gate must be a FAILURE rather than a quiet green build. `describeIfPg` and
 * its siblings exit zero with every test skipped, so without this the coverage
 * simply vanishes and nothing says so.
 *
 * WHY THIS IS SHARED NOW. Eleven packages carried a copy. They had not drifted
 * in BEHAVIOUR — the assertion was byte-identical in all ten service copies —
 * but they had drifted in text (three wordings, one with no docstring at all),
 * which is the copy-pasted-line class this repository keeps finding just before
 * it costs something. Two of the eleven had also grown real extra clauses
 * (identity's database-free run, e2e's stack gate), so the copies were becoming
 * genuinely different things under one name.
 *
 * THE TRADE-OFF, STATED. Eleven copies have one virtue: an edit can only break
 * one of them. Unifying trades that for the drift, so one careless edit here
 * now weakens eleven gates at once. That is paid for the only way it can be —
 * `evaluate` is a PURE function of an environment, and `test/ci-guard.spec.ts`
 * drives it over fabricated environments to prove it still refuses everything
 * the copies refused. The copies had no tests at all; a guard nobody tests is
 * the thing this whole exercise is about.
 *
 * IT IS THE ENV-VAR HALF ONLY, and always was: it proves a gate was ARMED, not
 * that a spec RAN. A suite whose every test is skipped still exits zero. The
 * stack workflow closes that second half structurally by running jest with
 * `--json` and asserting `numPassedTests` against a floor, and `ci.yml`'s
 * database-free step does the same with a pending-count assertion.
 */

/**
 * @typedef {object} CiGuardRule
 * @property {string} when   - env var whose presence is CI's PROMISE
 * @property {string} requires - env var that must then be truthy
 * @property {string} why    - what silently skips if it is not
 */

/**
 * @typedef {object} CiGuardOptions
 * @property {ReadonlyArray<CiGuardRule>} [alsoRequires]
 *   Extra promise/gate pairs beyond `CI` ⇒ `PG_TEST_URL`.
 * @property {string} [databaseFreeRunFlag]
 *   Names an env var that DECLARES a deliberately database-free CI run. It
 *   exempts the `PG_TEST_URL` rule and arms the opposite assertion — a run
 *   claiming to be database-free must actually be one — so the flag cannot be
 *   set alongside a live database to silence the guard.
 */

/** @typedef {{ name: string, satisfied: boolean }} CiGuardResult */

/**
 * Decide, for one environment, what this guard asserts and whether it holds.
 *
 * PURE, and that is the point: the registration below is three lines of jest
 * around it, so the logic can be driven over fabricated environments rather
 * than only over the one the runner happens to have.
 *
 * @param {Record<string, string | undefined>} env
 * @param {CiGuardOptions} [options]
 * @returns {CiGuardResult[]} one per assertion, in a stable order
 */
function evaluate(env, options = {}) {
  const { alsoRequires = [], databaseFreeRunFlag } = options;
  const declaredDatabaseFree =
    databaseFreeRunFlag !== undefined && env[databaseFreeRunFlag] === '1';

  /** @type {CiGuardResult[]} */
  const results = [
    {
      name: 'provides PG_TEST_URL in CI so integration suites cannot silently skip',
      // Exempt ONLY when the run declares itself database-free. Anything else
      // in CI without a database is the failure this guard exists for.
      satisfied: !env['CI'] || declaredDatabaseFree || Boolean(env['PG_TEST_URL']),
    },
  ];

  if (databaseFreeRunFlag !== undefined) {
    results.push({
      name: 'a run DECLARING itself database-free really is',
      // The other direction, and what keeps the flag from being a mute button:
      // set it beside a live PG_TEST_URL and this fails, so the only way to
      // satisfy both is to mean it.
      satisfied: !declaredDatabaseFree || !env['PG_TEST_URL'],
    });
  }

  for (const rule of alsoRequires) {
    results.push({
      name: `arms ${rule.requires} wherever ${rule.when} promises it — ${rule.why}`,
      satisfied: !env[rule.when] || Boolean(env[rule.requires]),
    });
  }

  return results;
}

/**
 * Register the guard as jest cases. Call at the top level of a spec file.
 *
 * @param {CiGuardOptions} [options]
 */
function ciGuard(options = {}) {
  describe('CI integration-test guard', () => {
    // Anti-vacuity: options that registered nothing would be a spec file that
    // asserts nothing while looking like a gate.
    const registered = evaluate(process.env, options);
    if (registered.length === 0) {
      throw new Error('ciGuard registered no assertions');
    }
    for (const { name } of registered) {
      it(name, () => {
        // Re-evaluated inside the case so a failure reports against the
        // environment at run time, not at collection time.
        const now = evaluate(process.env, options).find((r) => r.name === name);
        expect({ name, satisfied: now?.satisfied }).toEqual({ name, satisfied: true });
      });
    }
  });
}

module.exports = { ciGuard, evaluate };
