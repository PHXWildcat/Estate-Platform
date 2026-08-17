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
  coverageThreshold: { global: { statements: 64, branches: 50, functions: 58, lines: 64 } },
});
