'use strict';
// Floor just below the measured number with PG_TEST_URL set
// (68.89/67.2/70.76/67.61 at M9 PR2, which added the controller and
// error-filter specs after CI measured 61.2 — the PR1 floor had been set
// from a number this suite never produced in CI). main, migrate-cli and the
// SES transport are exercised end to end from apps/e2e (the settlement
// precedent) — run locally with PG_TEST_URL rather than lowering this.
// Ratchets toward 95/90; never lower this floor.
//
// Re-measured at 69.9/68.65/69.56/68.35 when the int suite gained the
// every-kind send loop (migration 002), and ratcheted UP to match.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 69, branches: 68, functions: 69, lines: 68 } },
});
