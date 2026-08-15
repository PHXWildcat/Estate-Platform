'use strict';
// Coverage floor: a few points below current, ratcheting toward 95/90.
// M14 PR3 (the verification surface) re-measured at 90.5/88.05/91.01/91.08 — the new
// identity-client spec lifted that file from 58% to 77% — and ratcheted UP.
module.exports = require('@estate/config/jest')(__dirname, {
  // RATCHETED at M10 PR4 from a measured --coverage run (86.07/85.36/85.52/
  // 86.68): the assistant client and its resolvers arrived with their own
  // specs. Never lowered.
  // M11 measured 86.13/84.55/86.20/86.68 with the conversation resolvers and
  // their client under test. Set just below, never above a measured run — the
  // M10 PR3 lesson about a floor nobody had run.
  // RATCHETED at M12 (the documents surface): measured 88.04/85.93/88.07/88.68
  // with the documents client, its error mapping and the intake collapsing
  // under test.
  // M13 re-measured after the profile client, the people resolvers and the link
  // ceremony: 90.23/87.5/90.58/90.83. Ratcheted up from 88/85/88/88 — never down.
  // Ratcheted up with M19 PR2's measured 91.61/89.16/92.05/92.11 — up, never down.
  // Ratcheted UP, never down. M20 PR2 measured 92.09/89.20/93.13/92.56 — the
  // address change arrived with its own specs on both sides of the wire, so
  // functions moved a point and the other three sit at their integer floor.
  coverageThreshold: { global: { statements: 92, branches: 89, functions: 93, lines: 92 } },
});
