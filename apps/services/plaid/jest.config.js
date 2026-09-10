'use strict';
// Coverage floor set near the LOCAL number: the full-flow integration suite
// (plaid.int.spec.ts) only runs in CI, so local coverage comes from the unit
// suites (config, gateway, webhook verifier, service, guards, authz).
// Ratchets toward 95/90 — never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  // RATCHETED BY M49 PR6 from 60/55/40/60, which had not moved since the
  // service was written. Calibrated on the run the header names — NO
  // PG_TEST_URL, the integration suite skipped — measured 74.27/66.66/54.47/
  // 73.02 (statements/branches/functions/lines), and set four-plus points
  // below each figure so an ordinary edit does not trip it. With Postgres the
  // same commit measures 89.26/76.7/91.86/88.84; the floor is a lower bound in
  // both configurations, which is identity's convention, not notifications'
  // (which calibrates WITH Postgres and says so). A first draft of this ratchet
  // set 85/70/85/85 against the with-Postgres figure and went red on every
  // machine without a database — caught by the PR's review, not by its
  // author's gate runs, which always had one. Never lowered.
  coverageThreshold: { global: { statements: 70, branches: 62, functions: 50, lines: 69 } },
});
