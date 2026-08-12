/**
 * Guard against silent coverage loss: the Postgres integration suites skip
 * when PG_TEST_URL is absent (fine locally, where no Postgres exists), but in
 * CI that absence must be a FAILURE, not a quiet green build.
 *
 * THIS PACKAGE HAS ONE CI RUN WHERE THE ABSENCE IS THE POINT. `ci.yml` runs
 * identity with no database, because `jest.config.js`'s coverage floor is
 * calibrated against exactly that number and nothing was measuring it — it had
 * drifted under and failed for anyone without Postgres while CI stayed green.
 * That step and this guard want opposite things from the same environment,
 * which the step's first CI run duly proved by failing here.
 *
 * The exemption is DECLARED and asserts its own precondition: a run claiming to
 * be database-free must actually be one, so the flag cannot be pasted into the
 * ordinary test step as a mute button. `@estate/config/ci-guard` holds the rule
 * and the tests that pin every configuration of it.
 */
import { ciGuard } from '@estate/config/ci-guard';

ciGuard({ databaseFreeRunFlag: 'IDENTITY_NO_DB_RUN' });
