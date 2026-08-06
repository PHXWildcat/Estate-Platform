'use strict';
// Coverage floor set near the LOCAL number: the full-flow integration suite
// (profile.int.spec.ts) only runs in CI, so local coverage comes from the unit
// suites (config, authz PEP, validation, contacts service). CI coverage is
// higher. Ratchets toward 95/90 — never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  // M13 PR1 re-measured (local, no PG: 73.44/71.47/50.34/71.17) and ratcheted up
  // from 62/58/40/60. With PG the same suites reach 87/77/85/86.
  coverageThreshold: { global: { statements: 72, branches: 70, functions: 49, lines: 70 } },
});
