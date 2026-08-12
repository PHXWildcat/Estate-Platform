/**
 * Guard against silent coverage loss: the Postgres integration suites skip
 * when PG_TEST_URL is absent (fine locally, where no Postgres exists), but in
 * CI that absence must be a FAILURE, not a quiet green build.
 *
 * The rule and its tests live in `@estate/config/ci-guard` — eleven packages
 * carried a copy of it, which had drifted in wording (and in one case lost its
 * docstring entirely) while nothing tested the assertion anywhere.
 */
import { ciGuard } from '@estate/config/ci-guard';

ciGuard();
