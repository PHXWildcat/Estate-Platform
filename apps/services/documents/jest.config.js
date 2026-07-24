'use strict';
// Coverage floor set near the LOCAL number: the Postgres integration suite
// (documents.int.spec.ts) only runs in CI, so local coverage comes from the
// unit suites (config, renderer, state machine, object stores, service,
// authz, events, schemas). CI coverage is higher. Ratchets toward 95/90 —
// never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 70, branches: 62, functions: 55, lines: 70 } },
});
