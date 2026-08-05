'use strict';
// Floor just below the measured numbers (72.29/70.10/66.12/72.38 at M10 PR1,
// measured with PG_TEST_URL set — the Postgres integration suite lifted these
// from 66.45/67.35/57.92/66.39, and the floor was ratcheted with them). M9 PR2
// found the notifications floor had been set from a figure CI never produced,
// so the gate was red on a suite that was actually passing: a coverage floor is
// only a control when it comes from a measured run of THIS suite, and an
// invented number is a bug whichever way it is wrong.
//
// Functions still lags because main.ts, migrate-cli.ts, the three HTTP read
// clients and the live-transport half of the gateway port are exercised end to
// end rather than from this package — the settlement precedent.
//
// RATCHETED at M10 PR3 (the analysers), from a run WITHOUT PG_TEST_URL:
// 82.21/78.78/72.99/81.58 locally, and CI measures higher because the Postgres
// integration suite covers more of the same source. So the floor below is a
// true lower bound in both configurations — set from a measured run of THIS
// suite, which is the M9 PR2 lesson about a floor invented from a number CI
// never produced.
// Ratchets toward 95/90; never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 81, branches: 78, functions: 72, lines: 81 } },
});
