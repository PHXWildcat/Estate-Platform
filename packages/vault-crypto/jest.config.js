'use strict';
// Pure functions with no PG gate, so the floor is high from day one and set
// just under the local numbers (99 / 94 / 100 / 100). The uncovered branches
// are unreachable guards (a wrapped key larger than 64 KiB, SRP ephemeral
// retries). Ratchets toward 95/90 - never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 97, branches: 92, functions: 95, lines: 97 } },
});
