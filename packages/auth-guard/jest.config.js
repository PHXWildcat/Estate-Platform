'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
// Raised from 85/80/85/85 when the credential graph landed with direct tests
// for `credentialsHeldIn` — the detector all eight services' config specs
// trust, so a blind spot in it would make their assertions pass vacuously.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 98, branches: 98, functions: 98, lines: 98 } },
});
