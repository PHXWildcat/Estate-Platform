'use strict';
// Floor set just below the CI-MEASURED number (61.18/47.33/63.19/60.63 with
// PG_TEST_URL set). CI always provides Postgres, so the integration suite
// counts; a run without it covers less, which is why the vault precedent of
// gating on the CI figure applies here — run locally with PG_TEST_URL rather
// than lowering this. Branch coverage lags because the controllers and the
// HTTP identity-lock/notifier adapters are exercised by the e2e in apps/e2e,
// not from this package. Ratchets toward 95/90 — never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 60, branches: 45, functions: 60, lines: 59 } },
});
