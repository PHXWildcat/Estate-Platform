'use strict';
// Floor set just below the CI-MEASURED number (61.87/44.93/56.96/61.54 with
// PG_TEST_URL set, after PR2). CI always provides Postgres, so the integration
// suite counts; a run without it covers less, which is why the vault precedent
// of gating on the CI figure applies here — run locally with PG_TEST_URL
// rather than lowering this.
//
// Branch and function coverage lag deliberately: the controllers and the HTTP
// identity-lock / notifier / settlement-client adapters are exercised end to
// end from apps/e2e, not from this package, and PR2 roughly doubled the
// service surface (staged access, tasks, distributions, authority) while its
// unit suites target the CONTROLS rather than every DTO mapper. Ratchets
// toward 95/90 — never lower this floor.
// M14 PR2 (the verified-recipient gates) re-measured at 62.18/47.51/57.32/61.94;
// ratcheted UP to match. Never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  // Ratcheted UP by M21 PR1: `operator-cli.ts` went from 0% — no test in the
  // repository had ever executed it — to 53%, its remainder being `main()` and
  // the `require.main` guard, which are the wiring the platform calls.
  //
  // RATCHETED UP AGAIN BY M49 PR3, and the size of the jump is the point: the
  // suite measures 72.68/70.62/64.66/72.16 (995/1369, 488/691, 183/283,
  // 941/1304, with PG_TEST_URL set — the configuration ci.yml runs) against a
  // floor of 64/50/58/64. Twenty points of branch coverage had accumulated with
  // nothing holding on to them; a floor left where it was while the run grows
  // around it stops being a floor and becomes slack, which is this package's
  // own M49 PR1 lesson about an anti-vacuity floor, one level up.
  //
  // NOT SET "JUST BELOW THE MEASUREMENT", and that is a deliberate departure
  // from what this file has done since it was written. At 72/70/64/72 the
  // headroom is TWO uncovered functions and TWO uncovered lines — 183/(283+x)
  // ≥ 0.64 gives x ≤ 2, 941/(1304+x) ≥ 0.72 gives x ≤ 2 — so the next PR's
  // first uncovered helper reds a gate that exists to catch regression, not to
  // pin a number. One point lower on each metric buys 32/16/7/21 by the same
  // arithmetic, and still ratchets branches from 50 to 69. Percentages hide
  // this; the raw counts above are the reason the arithmetic is written down.
  coverageThreshold: { global: { statements: 71, branches: 69, functions: 63, lines: 71 } },
});
