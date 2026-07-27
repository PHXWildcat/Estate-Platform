describe('CI integration-test guard', () => {
  it('provides PG_TEST_URL in CI so integration suites cannot silently skip', () => {
    if (process.env['CI']) {
      expect(process.env['PG_TEST_URL']).toBeTruthy();
    }
  });
});
