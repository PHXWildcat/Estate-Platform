/**
 * Guard against silent coverage loss: the Postgres integration suites skip
 * when PG_TEST_URL is absent (fine locally, where no Postgres exists), but in
 * CI that absence must be a FAILURE, not a quiet green build.
 *
 * ═══ AND CI NOW HAS ONE RUN WHERE THE ABSENCE IS THE POINT ═══
 *
 * `ci.yml` gained a step that runs this package with NO database, because
 * `jest.config.js`'s coverage floor is calibrated against exactly that number
 * and nothing was measuring it — it had drifted under and failed for anyone
 * without Postgres while CI stayed green. That step and this guard want
 * opposite things from the same environment, which the step's first CI run
 * duly proved by failing here.
 *
 * THE EXEMPTION IS DECLARED, NARROW, AND ASSERTS ITS OWN PRECONDITION. A run
 * that claims to be the no-database one must actually have no database, so the
 * flag cannot be pasted into the ordinary test step to silence the guard: it
 * would then fail the second case instead. The guard's intent survives intact —
 * integration suites must never skip in CI UNACCOUNTED FOR — and the one run
 * where they skip on purpose says so out loud and is checked on it.
 *
 * Only THIS package's guard is exempted, because only this package has the
 * step. The other ten copies are untouched and still refuse outright. (That
 * there are eleven near-identical copies of this file is the repo's own
 * copy-pasted-line drift class, noted rather than addressed here — unifying
 * them is a change to ten packages that has nothing to do with why this one
 * was edited.)
 */
const NO_DB_RUN = process.env['IDENTITY_NO_DB_RUN'] === '1';

describe('CI integration-test guard', () => {
  it('provides PG_TEST_URL in CI so integration suites cannot silently skip', () => {
    if (process.env['CI'] && !NO_DB_RUN) {
      expect(process.env['PG_TEST_URL']).toBeTruthy();
    }
  });

  it('a run DECLARING itself database-free really is', () => {
    // The other direction, and it is what keeps the flag from being a mute
    // button: set it alongside a live PG_TEST_URL and this fails, so the only
    // way to satisfy both cases is to mean it.
    if (NO_DB_RUN) {
      expect(process.env['PG_TEST_URL'] ?? '').toBe('');
    }
  });
});
