/**
 * Guard against silent coverage loss. Gated suites skip when their environment
 * is absent — fine locally, where the dependency may not exist — but where CI
 * PROMISES the environment, a missing gate must be a FAILURE, not a quiet
 * green build.
 *
 * This is the env-var half only: it proves a gate was ARMED, not that a spec
 * RAN — a suite whose every test is skipped still exits zero. The stack
 * workflow closes the second half structurally, running jest with `--json`
 * and asserting `numPassedTests` against a floor, so a silently skipped suite
 * turns the JOB red even though jest was green.
 */
describe('CI integration-test guard', () => {
  it('provides PG_TEST_URL in CI so integration suites cannot silently skip', () => {
    if (process.env['CI']) {
      expect(process.env['PG_TEST_URL']).toBeTruthy();
    }
  });

  it('arms the stack gate wherever the workflow declares the stack is up', () => {
    // The stack workflow sets CI_REQUIRE_STACK=1 once `compose up` succeeds.
    // From that point an unset STACK_TEST would make stack.e2e.spec.ts and
    // aws-conformance.spec.ts skip green; this converts that into red.
    if (process.env['CI_REQUIRE_STACK']) {
      expect(process.env['STACK_TEST']).toBeTruthy();
    }
  });
});
