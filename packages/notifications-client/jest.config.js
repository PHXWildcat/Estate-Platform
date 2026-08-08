'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
// M14 security review re-measured at 98/93.33/94.11/100; ratcheted UP. The review
// added the vault notification adapters' first specs and the client's
// transport-failure case.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 98, branches: 93, functions: 94, lines: 100 } },
});
