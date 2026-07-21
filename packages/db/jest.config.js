'use strict';
// Coverage floor set at the LOCAL number (integration suites, which cover the
// migrator/convention-checker, only run in CI — CI coverage is much higher).
// Ratchets toward 95/90 once CI numbers are captured over several runs.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 25, branches: 22, functions: 20, lines: 28 } },
});
