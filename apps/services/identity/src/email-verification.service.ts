import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { NOTIFICATIONS, type NotificationsPort } from '@estate/notifications-client';
import { AuthEventsRepo } from './auth-events.repo';
import { CLOCK, type Clock } from './di-tokens';
import {
  EmailVerificationRepo,
  MAX_VERIFY_ATTEMPTS,
  VerificationRaceError,
} from './email-verification.repo';
import { EventsService } from './events.service';
import { canonicalLengthFor, canonicalCode, readableCode, sha256 } from './readable-code';

/** How long a mailed code stays usable. */
export const VERIFICATION_TTL_MS = 30 * 60 * 1000;

/**
 * The floor between two mints for one user.
 *
 * It is STILL the only rate limit on this path and it is doing real work. M17
 * added bounds to login and register (docs/03 §6k); this route is authenticated
 * and behind neither of them, so the sentence that used to read "because there
 * is no rate-limiting machinery anywhere in this repo" is now narrower and no
 * weaker: the machinery exists and does not reach here. Without this floor,
 * anyone able to authenticate to an account can mail its address once per
 * request: for an account standing on somebody else's address — which is
 * precisely the situation verification exists to detect — that turns a stranger
 * into a mail-bomb target, and at volume it is a sender-reputation attack on
 * every other user's alerts (docs/03 §6c named exactly that as the real risk of
 * unverified addresses).
 *
 * Five minutes, chosen against the honest user's need rather than the
 * attacker's patience: a code that has not arrived in five minutes is one the
 * user will want to re-request, and one mail per five minutes per account is
 * not a flood at any volume of accounts an attacker can stand up.
 */
export const REISSUE_FLOOR_MS = 5 * 60 * 1000;

/** What a resend attempt did, so the caller can be truthful about it. */
export type ReissueOutcome = 'sent' | 'too_soon' | 'already_verified' | 'unavailable';

/**
 * THE ADDRESS-VERIFICATION CEREMONY (M14).
 *
 * WHAT WAS BROKEN. Three shipped controls refuse in production rather than
 * proceed silently — M6 emergency access (§5.2), M7 settlement intake and
 * review-approve (§5.1), M13's link ceremony (§6g) — on the rule that a
 * waiting period nobody can be told about is not a control. All three test
 * `deliversToRealChannels`, which is a hardcoded literal on whichever adapter
 * class the service's own NOTIFY_MODE selected. It asks whether SES is wired.
 * It never asks whether the stored address belongs to the owner, and cannot,
 * because it never looks at a recipient. Meanwhile identity fed the delivery
 * store whatever was typed, at registration and at every login, and
 * `users.email_verified_at` sat unread and unwritten since M1. So the gate was
 * satisfied, the escrow armed or the five-day clock started, and the owner's
 * ability to INTERRUPT — the entire content of §5.2 and of §5.1's control 3 —
 * was unenforced.
 *
 * The sharp part was an anti-correlation: the only self-heal was the
 * login-time re-feed, so the address was freshest for active users and
 * STALEST for the dormant owner a fraudulent death report actually targets —
 * and once status reaches `settlement`, login is blocked, so it could never
 * heal at all.
 *
 * IT FIRES AT FIRST AUTHENTICATED LOGIN, NOT AT REGISTRATION, and that is a
 * decision rather than a convenience. Registration is unauthenticated; a
 * notification kind firing there would be a mail-bomb primitive addressable by
 * anyone with a victim's address. This used to continue "and would need
 * rate-limiting machinery this repo does not have", which M17 falsified —
 * register carries an address-keyed bound now (docs/03 §6k). The decision is
 * unchanged and rests on the first clause: that bound is per-process and
 * best-effort, evadable by restart and by spraying, which is not what should
 * stand between an anonymous caller and the platform's outbound mail. docs/03
 * §6c's existing mitigation — "no notification kind fires at registration" —
 * stays literally true.
 *
 * THE PATTERN IS M13's, near-verbatim: randomBytes, a canonical fold onto a
 * read-aloud alphabet, store only sha256, a TTL, an attempt cap, ONE uniform
 * refusal for unknown/expired/spent/revoked/raced/mismatched, and free
 * re-issue that retires the previous code. The M13 review's two lessons are
 * baked in: the width is the security parameter so it is DERIVED and spec'd
 * rather than asserted in a comment, and the CANONICAL form is what gets
 * measured and hashed on both sides.
 *
 * WHAT THE CODE PROVES, precisely: that whoever holds this account's session
 * can also read mail at the address on file. Not that the address is
 * "correct", not that the human is who they say — those are different claims
 * and the arming gates only need this one.
 */
@Injectable()
export class EmailVerificationService {
  constructor(
    private readonly codes: EmailVerificationRepo,
    private readonly authEvents: AuthEventsRepo,
    private readonly events: EventsService,
    @Inject(NOTIFICATIONS) private readonly notifications: NotificationsPort,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /**
   * Whether the delivery store can provably reach this user.
   *
   * `null` is UNANSWERABLE and is passed through rather than flattened: the
   * login hook and the user-facing route want different things from an outage
   * (the first declines to mint, the second declines to claim anything), and
   * collapsing it here would make one of them lie.
   */
  async status(userId: string): Promise<{ verified: boolean } | null> {
    return this.notifications.recipientStatus(userId);
  }

  /**
   * The login hook: mint and mail a code if — and only if — the address is
   * unverified and no live code exists.
   *
   * FIRE-AND-FORGET AT THE CALL SITE, exactly like the recipient upsert it
   * follows (`auth.service.ts`), so login latency is never coupled to SES.
   * Every failure inside is swallowed into a recorded outcome; nothing here
   * can throw into the auth path.
   *
   * IDEMPOTENCE IS THE POINT. Without the two guards, every login mails
   * another code — an escalating annoyance for the user and, for an account
   * standing on somebody else's address, an unbounded one for a stranger.
   */
  async ensureVerificationRequested(userId: string): Promise<void> {
    try {
      const status = await this.status(userId);
      if (status === null || status.verified) {
        // Unanswerable ⇒ do NOT mint. A notifications service we cannot reach
        // is one that cannot mail the code either, so minting would burn the
        // user's one live code on a send that is about to fail. It self-heals
        // at the next login, which is the same self-heal the recipient upsert
        // relies on.
        return;
      }
      await this.mintAndSend(userId, { respectFloor: true });
    } catch {
      // The auth path must not learn about this. A missed verification is a
      // gate that keeps refusing, which is the safe direction; a login that
      // fails because SES is down is not.
    }
  }

  /**
   * The user asked for another code. Same machinery, an outcome the caller can
   * render, and no new capability: it can only ever mail the address already
   * on file for the calling user.
   */
  async reissue(userId: string): Promise<ReissueOutcome> {
    const status = await this.status(userId);
    if (status === null) {
      return 'unavailable';
    }
    if (status.verified) {
      return 'already_verified';
    }
    return this.mintAndSend(userId, { respectFloor: true });
  }

  private async mintAndSend(
    userId: string,
    opts: { respectFloor: boolean },
  ): Promise<ReissueOutcome> {
    const now = this.clock();

    // THE FLOOR KEYS ON THE LAST MINT, NOT ON A LIVE CODE (M14 review). It used
    // to be checked only when `findLive` returned a row — but a send that fails
    // RETIRES its code, so in exactly the state where sends are failing there
    // was no live code, the floor was skipped, and this route had no rate limit
    // at all. `lastMintedAt` answers the question the floor was always asking:
    // how recently did we mail this address.
    const lastMinted = await this.codes.lastMintedAt(userId);
    if (
      opts.respectFloor &&
      lastMinted !== null &&
      now.getTime() - lastMinted.getTime() < REISSUE_FLOOR_MS
    ) {
      return 'too_soon';
    }

    const live = await this.codes.findLive(userId, now);
    // RETIRE UNCONDITIONALLY, and this is the M14 review's worst finding fixed.
    // `revokeLive`'s predicate matches the PARTIAL UNIQUE INDEX, which cannot
    // carry an expiry clause; `findLive`'s carries the clock. Calling this only
    // when a code was LIVE meant a lapsed row kept occupying the index forever:
    // the next insert took the unique violation, `mintAndSend` answered
    // `too_soon`, and the account could never be verified again — so every M14
    // arming gate refused it permanently. Ignoring the first email was enough
    // to trigger it.
    const retired = await this.codes.revokeLive(userId, now);
    if (retired && live !== null) {
      // Audited only when a USABLE code was retired. Clearing a lapsed or
      // attempt-exhausted row is bookkeeping — it had already stopped working,
      // so recording it as a retirement would put a fact in the trail that did
      // not happen. (The repo's boolean was previously discarded here, which
      // audited retirements that retired nothing.)
      await this.authEvents.insert({ userId, kind: 'email_verification.reissued' });
    }

    const code = readableCode(EV_PREFIX);
    const expiresAt = new Date(now.getTime() + VERIFICATION_TTL_MS);
    try {
      await this.codes.insert({
        userId,
        // The CANONICAL form is what is hashed, so redemption can accept the
        // code as a human actually retypes it (see `canonicalCode`).
        codeSha256: sha256(canonicalCode(code)),
        expiresAt,
      });
    } catch (err) {
      if (err instanceof VerificationRaceError) {
        // A concurrent login won. A code IS live and has been mailed, which is
        // the state this call wanted to reach, so it is not a failure.
        return 'too_soon';
      }
      throw err;
    }

    const outcome = await this.notifications.sendAddressVerification({ userId, code });
    const delivered = outcome.accepted && outcome.delivered;
    if (!delivered) {
      // RETIRE THE CODE THE USER NEVER RECEIVED. Leaving it live would make the
      // idempotence guard above refuse to mint for a full TTL over a mail that
      // does not exist — the guard turning into a lockout. Retiring it means
      // the next login (or resend) tries again immediately.
      await this.codes.revokeLive(userId, now);
    }
    await this.authEvents.insert({
      userId,
      kind: 'email_verification.sent',
      decision: delivered ? 'delivered' : 'failed',
    });
    await this.events.emailVerificationSent(userId, delivered);
    return delivered ? 'sent' : 'unavailable';
  }

  /**
   * Redeem a code, as the account holder.
   *
   * THE CODE IS THE ONLY SELECTOR: this takes no user id from the request body
   * and the repo has no lookup that accepts one, so the route cannot be turned
   * into an oracle for whether a given account has a code outstanding. The
   * caller's own session supplies WHO, and the code must belong to them — a
   * signed-in attacker holding somebody else's code gets the same uniform
   * refusal as a guess, and cannot burn the victim's code either, because the
   * mismatch is checked before any state moves.
   *
   * EVERY FAILURE IS ONE ANSWER (`invalid_code`): unknown, malformed, expired,
   * spent, revoked, attempt-exhausted, belonging to someone else, or raced.
   * Distinguishing them would tell whoever holds a guess that their guess named
   * something real. The cost is a vaguer message for an honest user, paid down
   * by free re-issue.
   */
  async verify(userId: string, sessionId: string, code: string): Promise<void> {
    const canonical = canonicalCode(code);
    if (canonical.length !== CANONICAL_CODE_LENGTH) {
      // Measured on the CANONICAL form, not the raw submission: a body of
      // nothing but separators satisfies a raw length check and folds to the
      // empty string (the M13 round-3 finding, avoided rather than repeated).
      await this.recordFailure(userId, sessionId);
      throw invalidCode();
    }

    const row = await this.codes.findByCode(sha256(canonical));
    const now = this.clock();
    if (
      row === null ||
      row.verified_at !== null ||
      row.revoked_at !== null ||
      row.expires_at <= now ||
      row.attempts >= MAX_VERIFY_ATTEMPTS ||
      row.user_id !== userId
    ) {
      // Count against the CALLER'S OWN live code, whatever they submitted —
      // including a guess that resolved to nothing, which is what a wrong code
      // actually looks like (a different digest, so no row). Round 2 of the M14
      // review found the previous form unreachable: it took the resolved row's
      // id and ran only inside this already-dead branch, so `attempts` could
      // never move on a live code and the cap bounded nothing.
      //
      // Never somebody else's: keying on the caller means a signed-in attacker
      // who somehow guessed a digest still cannot exhaust a victim's attempts.
      await this.codes.countAttempt(userId, now);
      await this.recordFailure(userId, sessionId);
      throw invalidCode();
    }

    if (!(await this.codes.markVerified(row.id, now))) {
      // Lost a race with a concurrent redemption of the same code. Same
      // refusal; nothing moved.
      await this.recordFailure(userId, sessionId);
      throw invalidCode();
    }

    // THE CODE IS SPENT BEFORE THE STORE IS TOLD, and that ordering is
    // deliberate: the irreversible half of this ceremony is the vouching, so
    // it runs LAST (the M9 review's rule). If the mark-verified call fails, the
    // user has burned a code and is still unverified — annoying, recoverable
    // with a resend. The other order would leave a verified address behind a
    // code that is still live and still mailable.
    const marked = await this.notifications.markRecipientVerified({ userId });
    if (!marked.ok) {
      // The store has no live row to vouch for — never fed, soft-deleted, or
      // crypto-shredded — or it is unreachable. Either way the platform must
      // NOT report success: "your address is verified" about an address the
      // delivery store cannot reach is the exact false assurance this
      // milestone exists to remove.
      //
      // RECORDED AS AN OUTAGE, NOT AS A FAILED VERIFICATION (M14 review). The
      // user presented a CORRECT code — it has already been spent by the CAS
      // above — and the platform is what could not finish. Emitting
      // `email_verification.failed` here would put "this user failed a
      // verification" in the one trail an investigator reads to decide whether
      // somebody was guessing at a user's codes, and it inverts the M9 rule
      // that a control firing must not read as an outage by making an outage
      // read as a control firing.
      await this.authEvents.insert({
        userId,
        sessionId,
        kind: 'email_verification.unavailable',
      });
      await this.events.emailVerificationUnavailable(userId, sessionId);
      throw new BadRequestException({ error: 'verification_unavailable' });
    }

    await this.authEvents.insert({ userId, sessionId, kind: 'email_verification.verified' });
    await this.events.emailVerified(userId, sessionId);
  }

  private async recordFailure(userId: string, sessionId: string | null): Promise<void> {
    await this.authEvents.insert({
      userId,
      sessionId,
      kind: 'email_verification.failed',
    });
    await this.events.emailVerificationFailed(userId, sessionId);
  }
}

function invalidCode(): BadRequestException {
  return new BadRequestException({ error: 'invalid_code' });
}

/**
 * The code primitives moved to `readable-code.ts` in M16, when the extension
 * pairing ceremony became the THIRD consumer of a derivation that existed twice
 * byte-identically. Re-exported here so every existing importer — this
 * service's spec among them — is unchanged, and so there is still exactly one
 * definition rather than one definition and a forwarding copy.
 */
export { canonicalCode, CODE_RANDOM_BYTES } from './readable-code';

/** This ceremony's prefix. Constant, so it folds identically for every code. */
const EV_PREFIX = 'EV1-';

export const CANONICAL_CODE_LENGTH = canonicalLengthFor(EV_PREFIX);
