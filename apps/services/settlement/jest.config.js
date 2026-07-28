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
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 61, branches: 44, functions: 56, lines: 61 } },
});
