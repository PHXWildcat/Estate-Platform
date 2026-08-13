'use strict';
// Coverage floor set a few points under the LOCAL number (the chain/ingestor
// integration suites only run with PG_TEST_URL — CI coverage is much higher).
// Ratcheted 25/20/20/25 → 50/48/54/50 when M18 PR2's detector landed with its
// unit layer (measured 53.48/51.89/57.14/53.31 local, 2026-08-13). Never down.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 50, branches: 48, functions: 54, lines: 50 } },
});
