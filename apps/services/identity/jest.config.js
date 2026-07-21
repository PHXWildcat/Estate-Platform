'use strict';
// Coverage floor set near the LOCAL number (the full-flow integration suite
// only runs in CI — CI coverage is higher). Ratchets toward 95/90.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 55, branches: 55, functions: 22, lines: 55 } },
});
