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

// M49 PR6 calibrated this package's coverage floor on the run WITHOUT a
// database — identity's convention, and the reason identity's own guard takes
// this flag. CI runs that configuration in a step of its own, which needs an
// exemption from the rule above and, in the other direction, proof that a run
// declaring itself database-free really is one. Naming the flag here is what
// makes the floor a gate rather than a number nothing evaluates.
ciGuard({ databaseFreeRunFlag: 'PLAID_NO_DB_RUN' });
