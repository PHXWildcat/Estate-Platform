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
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 85, branches: 70, functions: 87, lines: 85 } },
});
