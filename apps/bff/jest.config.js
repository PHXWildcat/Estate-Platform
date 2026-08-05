'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
module.exports = require('@estate/config/jest')(__dirname, {
  // RATCHETED at M10 PR4 from a measured --coverage run (86.07/85.36/85.52/
  // 86.68): the assistant client and its resolvers arrived with their own
  // specs. Never lowered.
  // M11 measured 86.13/84.55/86.20/86.68 with the conversation resolvers and
  // their client under test. Set just below, never above a measured run — the
  // M10 PR3 lesson about a floor nobody had run.
  coverageThreshold: { global: { statements: 86, branches: 84, functions: 86, lines: 86 } },
});
