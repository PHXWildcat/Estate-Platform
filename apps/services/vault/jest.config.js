'use strict';
// Floors set just under the CI-measured numbers (87 / 73 / 89 / 87), which is
// what `pnpm test -- --coverage` produces with PG_TEST_URL set - the only way
// CI ever runs, enforced by test/ci-guard.spec.ts.
//
// Unlike the other services, almost all of this one's logic is a database
// transaction, so a no-Postgres run covers only ~45%. Setting the floor there
// to make a local `--coverage` run pass would gate at half the real number, so
// it gates the real one instead: locally, run the suite with PG_TEST_URL (see
// the README) when you want coverage. Ratchets toward 95/90 - never lower.
// M7 PR2 raised the measured numbers to 89.79/72.72/92.59/91.02 (the §6a
// settlement gate arrived with its own tests), so the floor ratchets UP.
// M14 PR2 (the verified-recipient gates) re-measured at 89.84/73.84/93.12/90.98;
// ratcheted UP to match. Never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 89, branches: 73, functions: 93, lines: 90 } },
});
