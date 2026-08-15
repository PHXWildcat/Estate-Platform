import { HttpException, HttpStatus, Inject, Injectable } from '@nestjs/common';
import { AuthEventsRepo } from './auth-events.repo';
import { CLOCK, type Clock } from './di-tokens';
import { EventsService } from './events.service';
import { boundExceeded } from './ledger-bound';
import { ACCOUNT_PASSWORD_BOUND } from './rate-bounds';

/**
 * THE GUESSING BOUND ON THE ACCOUNT PASSWORD, for every route that checks one.
 *
 * ═══ WHY THIS IS A SHARED GATE AND NOT A METHOD ON `AuthService` ═══
 *
 * The M17 PR6 review found `POST /v1/auth/password` verifying the current
 * password with no bound of any kind — twenty-five wrong guesses from one
 * stolen session, no refusal, and the twenty-sixth took the account over — and
 * fixed it there, as a private method, because that was the only route in the
 * repo that read the account password from an authenticated caller.
 *
 * M20 PR2 then added a second one. `POST /v1/auth/email/change/request` takes
 * the current password for the same reason (the stolen-session threat) and runs
 * the same gate order — conditional step-up, then the verification — with
 * nothing between them. The M20 PR5 review measured the consequence: on a
 * factorless account, which `SecondFactorGate` deliberately admits so the
 * bootstrap case stays reachable, that route is an unlimited password oracle
 * one hop away from the bounded one, and recovering the password there defeats
 * the bound rather than tripping it.
 *
 * A METHOD ON ONE SERVICE IS WHAT ALLOWED THAT. The bound was reachable only
 * from the class that happened to own it, so the second route did not so much
 * bypass the control as never meet it. The gate is the `SecondFactorGate`
 * answer to the identical problem: a rule two services need becomes a thing
 * both can inject, with a name a fence can anchor on.
 *
 * ═══ ONE BUDGET, NOT TWO ═══
 *
 * Both routes read ONE secret, so they share ONE budget — the M16 rule that a
 * chokepoint is the SET of routes that read a factor, learned when the step-up
 * cap turned out to be bypassable through `POST /v1/auth/totp/verify`, which
 * checked the same `mfa_methods` row and wrote a kind the cap did not count.
 * Two bounds of five would simply be a bound of ten to anyone willing to
 * alternate. So `ACCOUNT_PASSWORD_BOUND.failures` names both routes' failure
 * kinds and `rate-bounds.spec.ts` holds the set to the routes that write into
 * it.
 *
 * ═══ WHAT THE CALLER STILL OWNS ═══
 *
 * Recording the FAILURE stays with each route, and deliberately: the two write
 * different kinds (`password.change_failed`, `email_change.denied`), each of
 * which means something specific in the ledger beyond feeding this counter, and
 * collapsing them into one kind emitted from here would cost an investigator
 * the ability to tell which ceremony was being guessed at. What the routes must
 * NOT own is the decision, which is why that half is here.
 */
@Injectable()
export class AccountPasswordGate {
  constructor(
    private readonly authEvents: AuthEventsRepo,
    private readonly events: EventsService,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /**
   * Refuse before the guess is scored.
   *
   * Called AFTER the factor gate — an account holding a verified factor never
   * reaches a password check at all, so this is the backstop for the factorless
   * case the gate lets through — and BEFORE the verification, because a bound
   * evaluated after the password is checked is not a bound, and because the
   * refusal's timing must not vary with whether the guess was right.
   */
  async assertAttemptsAvailable(userId: string, sessionId: string): Promise<void> {
    const overCap = await boundExceeded(
      this.authEvents,
      this.clock(),
      ACCOUNT_PASSWORD_BOUND,
      userId,
      sessionId,
    );
    if (overCap) {
      await this.refuse(userId, sessionId, overCap.count);
    }
  }

  /**
   * 429 with its own token, on the step-up refusal's reasoning: both routes
   * already required a resolved, authenticated caller, so a distinct status
   * tells them something about themselves and no one else. Never
   * `invalid_credentials`, which already means "that password was wrong" and
   * would send someone to re-check a password when the remedy is to wait.
   *
   * Its own ledger kind, NOT either route's failure kind — a refusal counted by
   * the bound that produced it feeds its own counter, and a retrying client
   * would lock its user out for as long as it kept trying (the M16 lesson).
   *
   * THE KIND STILL READS `password.change_rate_limited` though the bound now
   * covers two routes, and that is deliberate rather than left over. Renaming a
   * ledger kind is free; renaming the AUDIT ACTION beside it is not — an audit
   * consumer that has not been deployed yet rejects an action it does not know
   * as a `schema_violation`, which is the recorded deploy-order hazard, and it
   * would buy nothing but a tidier string. The kind names the BOUND, and the
   * bound's canonical route is the password change.
   */
  private async refuse(userId: string, sessionId: string, attempts: number): Promise<never> {
    await this.authEvents.insert({
      userId,
      sessionId,
      kind: ACCOUNT_PASSWORD_BOUND.refusalKind,
      decision: 'too_many_attempts',
    });
    await this.events.passwordChangeRateLimited(userId, sessionId, attempts);
    throw new HttpException({ error: 'too_many_attempts' }, HttpStatus.TOO_MANY_REQUESTS);
  }
}
