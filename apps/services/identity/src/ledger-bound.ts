import type { LedgerRateBound } from './rate-bounds';

/**
 * Counting a ledger bound, in ONE place, because two services now need the
 * answer.
 *
 * This was `AuthService.boundExceeded` — private, and correct there while
 * every bounded route lived in that class. M20 PR5 found a route that reads the
 * account password in a DIFFERENT service with no bound at all, and the fix
 * needs the same count from `EmailChangeService`. A second copy of a
 * fifteen-line predicate is the M8 PR2 shape (seven byte-identical audit
 * producers sharing one bug), so the predicate moved out rather than being
 * written twice: `AuthService` still calls it for the step-up and login bounds,
 * the account-password gate calls it for its own, and there is one definition
 * of "how many failures since the last success".
 *
 * The repo arrives as a STRUCTURAL parameter rather than an injected class so
 * this module stays a pure function of its inputs — it has no lifecycle, no
 * state and nothing to construct, and a test can drive it with a counter rather
 * than a Nest container.
 */
export interface FailedAttemptCounter {
  failedAttempts(
    userId: string,
    since: Date,
    opts: {
      readonly failures: readonly string[];
      readonly successes: readonly string[];
      readonly sessionId?: string;
    },
  ): Promise<number>;
}

/**
 * TWO SCOPES, AND THE SESSION ONE IS CHECKED FIRST, for M16's reason: the
 * per-session budget is what a stolen credential exhausts on ITSELF, so the
 * refusal cannot become a lockout of the owner, who reaches the same route from
 * their own sessions with their own budgets. The account ceiling stays as the
 * real bound against somebody holding several stolen sessions.
 *
 * `scopeId === null` (login, where there is no credential at the point of
 * failure) skips the session half entirely; `maxPerScope === null` says the
 * bound has no session budget to begin with.
 */
export async function boundExceeded(
  authEvents: FailedAttemptCounter,
  now: Date,
  bound: LedgerRateBound,
  userId: string,
  scopeId: string | null,
): Promise<{ scope: 'session' | 'account'; count: number } | null> {
  const windowStart = new Date(now.getTime() - bound.windowMs);
  const counted = { failures: bound.failures, successes: bound.successes };

  if (scopeId !== null && bound.maxPerScope !== null) {
    const mine = await authEvents.failedAttempts(userId, windowStart, {
      ...counted,
      sessionId: scopeId,
    });
    if (mine >= bound.maxPerScope) {
      return { scope: 'session', count: mine };
    }
  }
  const account = await authEvents.failedAttempts(userId, windowStart, counted);
  return account >= bound.maxPerAccount ? { scope: 'account', count: account } : null;
}
