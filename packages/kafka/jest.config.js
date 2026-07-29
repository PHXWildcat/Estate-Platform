'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
//
// Branches sit lower than the rest because two arms are unreachable without a
// live broker: the `?? new Kafka(...)` defaults that build a real producer and
// a real admin when no double is injected. Everything they guard is exercised
// through the injected doubles, and the stack test (M8 PR4) drives the real
// ones against Redpanda.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 95, branches: 85, functions: 95, lines: 95 } },
});
