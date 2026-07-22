'use strict';
// Coverage floor set near the LOCAL number: the full-flow integration suite
// (assets.int.spec.ts) only runs in CI, so local coverage comes from the unit
// suites (config, reducer, service, guards, authz, events). CI coverage is
// higher. Ratchets toward 95/90 — never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 60, branches: 55, functions: 40, lines: 60 } },
});
