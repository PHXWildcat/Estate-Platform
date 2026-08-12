/**
 * Types for `ci-guard.js`. Hand-written for the same reason `jest.js` has no
 * types at all: this package is plain CommonJS consumed by config files, and
 * adding a build step to it would put a compile between every package and its
 * jest configuration.
 */

export interface CiGuardRule {
  /** Env var whose presence is CI's PROMISE that the dependency is up. */
  readonly when: string;
  /** Env var that must then be truthy, or a gated suite skips green. */
  readonly requires: string;
  /** What silently skips when it is not — read out in the case name. */
  readonly why: string;
}

export interface CiGuardOptions {
  /** Extra promise/gate pairs beyond `CI` ⇒ `PG_TEST_URL`. */
  readonly alsoRequires?: ReadonlyArray<CiGuardRule>;
  /**
   * Names an env var that DECLARES a deliberately database-free CI run
   * (set to `'1'`). It exempts the `PG_TEST_URL` rule and arms the opposite
   * assertion — such a run must really have no database — so the flag cannot
   * be set beside a live database to silence the guard.
   */
  readonly databaseFreeRunFlag?: string;
}

export interface CiGuardResult {
  readonly name: string;
  readonly satisfied: boolean;
}

/** Register the guard as jest cases. Call at the top level of a spec file. */
export function ciGuard(options?: CiGuardOptions): void;

/** The pure decision, exported so it can be driven over fabricated environments. */
export function evaluate(
  env: Record<string, string | undefined>,
  options?: CiGuardOptions,
): CiGuardResult[];
