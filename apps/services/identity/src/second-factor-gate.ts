import { ForbiddenException, Injectable } from '@nestjs/common';
import type { SessionContext } from '@estate/auth-guard';
import { MfaRepo } from './mfa.repo';
import { isStepUpFresh } from './stepup';
import { WebAuthnRepo } from './webauthn.repo';

/**
 * MAY THIS CALLER ADD AN AUTHENTICATION FACTOR TO THIS ACCOUNT?
 *
 * ═══ THE RULE, AND WHY IT IS CONDITIONAL ═══
 *
 * "You may add your FIRST factor with a session; you may add another only by
 * proving the one you already have."
 *
 * The conditional half is forced, not chosen. Step-up requires a verified
 * factor, so an unconditional guard on an enrolment route would make a second
 * factor unreachable forever for an account that has none. The bootstrap
 * therefore stays open, and that residual is stated in docs/03 §6j rather than
 * implied — an account with no factor has no proof to demand, and identity
 * cannot even warn the owner, because M14 deliberately made it not a holder of
 * the notifications SEND credential.
 *
 * ═══ WHY IT IS ONE PREDICATE ACROSS BOTH FACTOR TYPES ═══
 *
 * The M16 PR5 review found this as TOTP-only and fixed it as TOTP-only, in
 * `AuthService.enrollTotp` against `MfaRepo.hasVerifiedTotp`. Verifying THAT
 * fix against real Postgres found the same escalation still open through
 * WebAuthn, and worse in one respect: a caller holding nothing but a stolen
 * session could complete `webauthn/register/options` then
 * `webauthn/register/verify` with an authenticator OF THEIR OWN, then
 * `webauthn/authenticate/verify` — measured, and the attacker's session row came
 * back `mfa_level=stepup` with a live `stepup_expires_at`. `excludeCredentials`
 * looks protective and is not: it stops re-registering the SAME authenticator,
 * never a different one.
 *
 * It is also QUIETER than the TOTP version. That one locked the owner out —
 * `findActiveTotp` takes the newest, so their own codes started failing, which
 * is a signal. Here the victim's existing factors keep working, so nothing they
 * can observe changes.
 *
 * A PER-TYPE PREDICATE WOULD HAVE LEFT A HOLE IN BOTH DIRECTIONS, which is the
 * reason this is one question rather than two. `hasVerifiedTotp` is false for a
 * user who holds only a passkey — so under the TOTP-only fix, a stolen session
 * could still enrol TOTP on a passkey-protected account and elevate with it.
 * The question that has to be asked is "does this account hold ANY factor it
 * could be made to prove", so both stores are consulted and either one arms the
 * gate.
 *
 * ═══ WHY IT IS A SERVICE-LEVEL GATE AND NOT A `StepUpGuard` ═══
 *
 * The CONDITION is service state — whether this account already holds a factor
 * — which a route decorator cannot see. That is a real cost: every fence in
 * this repo that checks step-up gating scans for the decorator, so a gate that
 * lives here is invisible to them. `test/factor-routes.spec.ts` exists to close
 * exactly that gap, and it is why this method has a name a scan can anchor on
 * rather than being three inlined lines.
 */
@Injectable()
export class SecondFactorGate {
  constructor(
    private readonly mfa: MfaRepo,
    private readonly webauthn: WebAuthnRepo,
  ) {}

  /**
   * Does this account already hold a factor it could be made to prove?
   *
   * Either store arms it. Deliberately NOT "and": a user with a passkey and no
   * TOTP is as provable as one with both, and asking for both would make the
   * gate silently inert for everyone who holds exactly one.
   */
  async holdsVerifiedFactor(userId: string): Promise<boolean> {
    if (await this.mfa.hasVerifiedTotp(userId)) return true;
    return this.webauthn.hasCredentials(userId);
  }

  /**
   * Refuse an attempt to ADD a factor unless the caller proved one — when there
   * is one to prove.
   *
   * Applies the SAME predicate `StepUpGuard` does, from the shared definition,
   * because a second notion of freshness here would be a second notion free to
   * drift from the one every other gated route uses.
   */
  async assertMayAddFactor(
    userId: string,
    caller: Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'>,
    now: Date,
  ): Promise<void> {
    if (!(await this.holdsVerifiedFactor(userId))) {
      return; // the bootstrap: nothing exists to prove
    }
    if (!isStepUpFresh(caller.mfaLevel, caller.stepupExpiresAt, now)) {
      throw new ForbiddenException({ error: 'stepup_required' });
    }
  }
}
