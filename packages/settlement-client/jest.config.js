'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 90, branches: 85, functions: 90, lines: 90 } },
});
