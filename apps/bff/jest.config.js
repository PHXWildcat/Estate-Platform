'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
module.exports = require('@estate/config/jest')(__dirname, {
  // RATCHETED at M10 PR4 from a measured --coverage run (86.07/85.36/85.52/
  // 86.68): the assistant client and its resolvers arrived with their own
  // specs. Never lowered.
  coverageThreshold: { global: { statements: 85, branches: 84, functions: 85, lines: 86 } },
});
