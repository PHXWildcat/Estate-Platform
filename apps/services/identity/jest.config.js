'use strict';
// Coverage floor set near the LOCAL number (the full-flow integration suites
// only run with PG_TEST_URL — CI coverage is higher, 87.2/78.2/79.0/86.7 at
// M16 PR5). Ratchets toward 95/90; never lower this floor.
//
// Re-measured at 65.23/66.35/30.72/63.39 locally when M14 added the
// address-verification ceremony and its specs, and ratcheted UP to match.
//
// ═══ AND THEN IT DRIFTED UNDER, UNWATCHED, UNTIL M16 PR5 ═══
//
// Measured at 62.24/66.60/28.43/60.24 at b96ab92 — below this floor on
// statements, lines AND functions, and failing for anyone who ran the suite
// without Postgres. Nobody saw it because THIS CONFIGURATION IS THE ONE NOTHING
// RUNS: `ci.yml` sets `PG_TEST_URL`, so the number CI measures is the high one
// and the number this floor is calibrated against is measured by no gate at
// all. A floor nothing enforces is the fence-that-never-runs shape, arrived at
// from the other direction — not a scan that stopped matching, but a threshold
// nothing evaluates.
//
// Closed by giving `auth.controller.ts` its first unit spec (23 route handlers
// at 0% functions without Postgres, because only the int suites reached them),
// which took the local number to 67.91/67.55/39.25/66.23 — the M9 PR2 remedy
// for the identical problem in notifications, where the floor "was set from a
// number CI never produced". Ratcheted UP to match, and it is worth saying
// plainly that ratcheting is the only move available here: lowering it would
// have hidden the drift that made it fail.
//
// AND IT IS NOW ENFORCED: `ci.yml` runs identity with no database, asserting
// that the integration suites really did skip so the step cannot pass while
// measuring the run above. That step is what caught this floor slipping when
// `SecondFactorGate` arrived — its methods are exercised by the Postgres-backed
// specs, so without a unit spec the database-free number fell under on
// functions. `second-factor-gate.spec.ts` is that spec, and it is owed on its
// own terms: the int suites prove the SQL predicate, this one proves the
// DECISION the three inputs combine into.
//
// Re-measured at 68.59/68.19/39.90/66.89 and ratcheted UP.
module.exports = require('@estate/config/jest')(__dirname, {
  // Ratcheted UP again for M17 PR2 (was 70/68/41/68 after PR1, 68/68/39/66
  // before it). Measured on the DATABASE-FREE run, which is the configuration
  // `ci.yml` evaluates this against — the 2026-08-12 lesson that a floor
  // calibrated for a run nothing performs is a floor nothing evaluates.
  //
  // PR2's new code is mostly SQL, which the PG-gated int suite proves and this
  // run cannot see, so the floor initially DROPPED. It was not lowered: the
  // answer was `test/db.spec.ts`, which covers `withTransaction`'s failure
  // paths (rollback, release, a failing rollback not masking the original
  // error) — control flow rather than SQL semantics, and owed on its own terms
  // regardless of the number.
  // M17 PR3 LOWERS THIS, and it is written here rather than quietly applied.
  //
  // PR1 and PR2 both raised it; this one drops it 70/68/42/69 → 69/67/41/68,
  // and the whole difference is `password-reset.repo.ts`. That file is SQL —
  // a partial-unique-index retirement, a CAS spend, a digest lookup — and this
  // run has no database, so every line of it is uncovered here and every line
  // of it is covered by `password-reset.int.spec.ts` where the statements
  // actually execute. A unit test over a faked repo would raise the number and
  // measure nothing, which is the shape this repo has rejected twice.
  //
  // What was NOT done in place of lowering: excluding repo files from coverage
  // (that hides real gaps in the files that hold the predicates), or contriving
  // assertions to reach uncovered branches (which measures the contrivance).
  // What WAS done first: `password-reset-bound.spec.ts` covers the DECISION
  // layer — the mis-shaped code, and every dead-row branch refusing identically
  // without spending or hashing — because those are choices over repo answers
  // rather than SQL, and they were owed regardless of the number.
  // M17 PR4 RATCHETS BACK UP, 69/67/41/68 → 70/67/43/69: the ceremony's
  // decision layer, its audit emitters and its refusal branches are all
  // proven without a database, so the number the PR3 exception traded away
  // comes back with interest. The remaining no-DB gap is exactly the two
  // SQL-only repo files, which the int suites execute for real.
  // M21 PR3a ratchets again, measured 72.21/67.4/45.16/71.03 on the
  // database-free run. `handoff.service.ts` went 36.84 -> 100 statements and
  // 0 -> 100 functions: the two handoff files were the last decision layer in
  // this service that only a Postgres-backed suite ever executed, so adding
  // the operator mint route meant the audience threading, the audience-blind
  // redemption and the three subtractions that make a stolen code cheap were
  // asserted only where a PG_TEST_URL happened to be set. `handoffs.repo.ts`
  // stays SQL-only and int-covered, which is the split this floor exists to
  // accommodate. Never lowered.
  coverageThreshold: { global: { statements: 72, branches: 67, functions: 45, lines: 71 } },
});
