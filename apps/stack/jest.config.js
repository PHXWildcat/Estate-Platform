'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
//
// The three `*-cli.ts` entrypoints and `index.ts` are excluded, not exempted.
// Each CLI ends in a top-level `process.exitCode = main(...)` (the repo's
// existing CLI shape), so importing one to test it would RUN it. Rather than
// leave their behaviour untested, the parts worth testing were moved into
// `generate-env.ts` and `doctor.ts` — the overwrite refusal, every diagnostic,
// the whole credential derivation — leaving argv parsing and exit codes behind.
//
// Scoping the measurement to what remains is stronger than a global floor
// diluted to ~67% by four wiring files: it means a regression in the logic
// cannot hide behind entrypoints that were never going to be covered.
module.exports = require('@estate/config/jest')(__dirname, {
  collectCoverageFrom: ['src/**/*.ts', '!src/**/*-cli.ts', '!src/index.ts'],
  coverageThreshold: { global: { statements: 97, branches: 93, functions: 97, lines: 97 } },
});
