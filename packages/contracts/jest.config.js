'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
// (Low function coverage is expected — contracts is mostly zod schema data.)
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 45, branches: 90, functions: 5, lines: 48 } },
});
