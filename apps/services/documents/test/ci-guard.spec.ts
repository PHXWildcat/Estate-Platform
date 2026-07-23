/**
 * Guard against silent coverage loss: the Postgres integration suite skips when
 * PG_TEST_URL is absent (fine locally, where no Postgres exists), but in CI
 * that absence must be a FAILURE, not a quiet green build.
 */
describe('CI integration-test guard', () => {
  it('provides PG_TEST_URL in CI so integration suites cannot silently skip', () => {
    if (process.env['CI']) {
      expect(process.env['PG_TEST_URL']).toBeTruthy();
    }
  });
});
