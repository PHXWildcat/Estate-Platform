'use strict';
// This package is plain CommonJS consumed by every other package's
// `jest.config.js`, so it has no `src/` to measure — `collectCoverageFrom` is
// pointed at the one module that carries logic rather than at a directory that
// does not exist. No floor: the spec drives `evaluate` exhaustively over
// fabricated environments, and a percentage would say less than that does.
module.exports = require('./jest')(__dirname, {
  collectCoverageFrom: ['ci-guard.js'],
});
