'use strict';
// Coverage floor set near the LOCAL number: the full-flow integration suite
// (profile.int.spec.ts) only runs in CI, so local coverage comes from the unit
// suites (config, authz PEP, validation, contacts service). CI coverage is
// higher. Ratchets toward 95/90 — never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 62, branches: 58, functions: 40, lines: 60 } },
});
