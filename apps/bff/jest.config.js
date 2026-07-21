'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 80, branches: 82, functions: 78, lines: 82 } },
});
