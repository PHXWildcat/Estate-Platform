'use strict';
// Coverage floor set a few points under the LOCAL number (the chain/ingestor
// integration suites only run with PG_TEST_URL — CI coverage is much higher).
// Ratcheted 25/20/20/25 → 50/48/54/50 when M18 PR2's detector landed with its
// unit layer, then → 57/52/55/57 when PR3's review added the connection
// wrapper and its spec (measured 59.04/54.11/57.5/59.17 local, 2026-08-13).
// Never down.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 57, branches: 52, functions: 55, lines: 57 } },
});
