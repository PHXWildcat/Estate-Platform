'use strict';
// Coverage floor set near the LOCAL number: the full-flow integration suite
// (profile.int.spec.ts) only runs in CI, so local coverage comes from the unit
// suites (config, authz PEP, validation, contacts service). CI coverage is
// higher. Ratchets toward 95/90 — never lower this floor.
module.exports = require('@estate/config/jest')(__dirname, {
  // M13 PR3 RE-ANCHORS this floor to the WITH-PG measurement — 87.68/76.45/86.81/
  // 86.82, measured, ratcheted up from 72/70/49/70 — because the old no-PG anchor
  // stopped meaning anything. The link ceremony, the transactional delete and the
  // two uniqueness migrations are all exercised by Postgres-backed suites, so a
  // no-PG run now reports 68/69/44/66: the same code, six of thirteen suites
  // skipped. Calibrating a floor to a partial run makes the number drift downward
  // every time a database-backed control is added, which is the wrong direction for
  // exactly the code that most needs covering.
  //
  // CONSEQUENCE, stated rather than discovered: `pnpm test --coverage` for this
  // package now REQUIRES `PG_TEST_URL` (every CI workflow sets it; docs/05 has the
  // local stack). Without it the suites still run — they skip — but the threshold
  // fails, which is more honest than a green bar over a third of the service.
  coverageThreshold: { global: { statements: 87, branches: 76, functions: 86, lines: 86 } },
});
