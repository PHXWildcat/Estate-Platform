'use strict';
// Pure functions with no PG gate, so the floor is high from day one and set
// just under the local numbers (99 / 94 / 100 / 100). The uncovered branches
// are unreachable guards (a wrapped key larger than 64 KiB, SRP ephemeral
// retries). Ratchets toward 95/90 - never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  /*
   * Resolve relative `.js` specifiers to the TypeScript sources, explicitly.
   *
   * M15 PR2 gave every relative import an explicit `.js`, because the browser
   * build emits native ES modules and a browser will not guess the extension.
   * Without this mapper jest's resolution of `./bigint.js` depends on
   * `dist/` — moving `dist/` aside makes every import fail with "Cannot find
   * module './bigint.js' from 'src/srp.ts'", and a run against a STALE dist was
   * observed reporting 10.68% coverage, with only the two files that have no
   * relative imports instrumented.
   *
   * Both symptoms proved cache-sensitive and neither reproduces reliably once
   * `dist` is current, so the mechanism is recorded as observed rather than
   * explained. What is not in doubt is the fix: this mapper makes the suite
   * read `src` regardless of whether a build artifact exists or how old it is,
   * which is the 2026-08-06 rule (a stale artifact is not evidence about
   * source) enforced rather than hoped for.
   */
  moduleNameMapper: { '^(\\.{1,2}/.*)\\.js$': '$1' },
  coverageThreshold: { global: { statements: 97, branches: 92, functions: 95, lines: 97 } },
});
