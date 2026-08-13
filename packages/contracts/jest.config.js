'use strict';
// Coverage floor: a few points below current (99.24/100/29.82/99.24 measured
// 2026-08-13, after the M18 decrypt-prefix fence started executing the
// registry and, through the barrel, most schema modules). Ratcheted up from
// 45/90/5/48 — never down. (Function coverage stays low by nature — contracts
// is mostly zod schema data.)
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 97, branches: 95, functions: 25, lines: 97 } },
});
