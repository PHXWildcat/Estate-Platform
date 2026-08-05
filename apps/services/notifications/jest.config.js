'use strict';
// Floor just below the measured number with PG_TEST_URL set
// (68.89/67.2/70.76/67.61 at M9 PR2, which added the controller and
// error-filter specs after CI measured 61.2 — the PR1 floor had been set
// from a number this suite never produced in CI). main, migrate-cli and the
// SES transport are exercised end to end from apps/e2e (the settlement
// precedent) — run locally with PG_TEST_URL rather than lowering this.
// Ratchets toward 95/90; never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 67, branches: 65, functions: 69, lines: 66 } },
});
