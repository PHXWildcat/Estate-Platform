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
  // Ratcheted UP for M17's bounds (was 68/68/39/66). Measured on the
  // DATABASE-FREE run, which is the configuration `ci.yml` evaluates this
  // against — the 2026-08-12 lesson that a floor calibrated for a run nothing
  // performs is a floor nothing evaluates.
  coverageThreshold: { global: { statements: 70, branches: 68, functions: 41, lines: 68 } },
});
