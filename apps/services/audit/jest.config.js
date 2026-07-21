'use strict';
// Coverage floor set at the LOCAL number (the chain/ingestor integration suite
// only runs in CI — CI coverage is much higher). Ratchets toward 95/90.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 25, branches: 20, functions: 20, lines: 25 } },
});
