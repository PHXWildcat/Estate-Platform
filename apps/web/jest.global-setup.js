/**
 * PINS THE SUITE'S TIMEZONE, and it has to happen HERE.
 *
 * Why it exists (M23 PR3). `settlement_tasks.due_at` is a Postgres `date` that
 * the service widens to UTC midnight on the way out, so rendering it as an
 * INSTANT in the reader's zone loses a day for everyone west of UTC. The
 * browser found it at `America/Phoenix`; a suite running in UTC cannot see the
 * defect at all, because in UTC the correct and incorrect renderings agree.
 *
 * Why not in the test file. `process.env.TZ = …` inside a jest jsdom test is
 * INERT: the environment's `Intl` has already resolved its default zone, and
 * the assignment changes neither `Intl.DateTimeFormat().resolvedOptions()` nor
 * `toLocaleDateString`. Probed directly rather than assumed — it reports the
 * new value in plain Node and the old one under jsdom. The first version of
 * that test therefore "forced" nothing and passed locally only because this
 * machine already sat in Phoenix, which is the same class of mistake as the
 * defect it was written for: an observer that cannot fail.
 *
 * `globalSetup` runs in the parent process BEFORE the workers fork, so the
 * value is in the environment when each worker's ICU default is first read.
 *
 * The zone is a fixed non-UTC one on purpose — a deterministic suite, and one
 * that can still tell a calendar day from a moment. The tests that depend on it
 * assert the zone is not UTC, so this going inert fails loudly instead of
 * quietly passing.
 */
module.exports = () => {
  process.env.TZ = 'America/Phoenix';
};
