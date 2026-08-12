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
// STILL TRUE, AND THE REASON THIS CAN DRIFT AGAIN: no CI job runs identity
// without `PG_TEST_URL`. Until one does, this floor is enforced by developers
// on machines with no database and by nothing else.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 67, branches: 67, functions: 39, lines: 66 } },
});
