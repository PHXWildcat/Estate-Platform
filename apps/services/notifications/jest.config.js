'use strict';
// Floor just below the measured number with PG_TEST_URL set
// (65.12/55.83/66.66/65.01 at M9 PR1). The controller, the error filter,
// main, and the SES transport are exercised end to end from apps/e2e (the
// settlement precedent) — run locally with PG_TEST_URL rather than lowering
// this. Ratchets toward 95/90; never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 63, branches: 53, functions: 64, lines: 63 } },
});
