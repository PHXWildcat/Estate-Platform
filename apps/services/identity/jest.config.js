'use strict';
// Coverage floor set near the LOCAL number (the full-flow integration suites
// only run with PG_TEST_URL — CI coverage is higher, 87.7/77.4/83.1/87.2 at
// M14). Ratchets toward 95/90; never lower this floor.
//
// Re-measured at 65.23/66.35/30.72/63.39 locally when M14 added the
// address-verification ceremony and its specs, and ratcheted UP to match.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 65, branches: 66, functions: 30, lines: 63 } },
});
