'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 85, branches: 80, functions: 85, lines: 85 } },
});
