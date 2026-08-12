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
import { ciGuard } from '@estate/config/ci-guard';

ciGuard({
  alsoRequires: [
    {
      when: 'CI_REQUIRE_STACK',
      requires: 'STACK_TEST',
      why: 'stack.e2e.spec.ts and aws-conformance.spec.ts skip green without it',
    },
  ],
});
