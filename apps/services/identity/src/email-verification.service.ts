import { createHash, randomBytes } from 'node:crypto';
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

/** How long a mailed code stays usable. */
export const VERIFICATION_TTL_MS = 30 * 60 * 1000;

/**
 * The floor between two mints for one user.
 *
 * It is the ONLY rate limit on this path and it is doing real work, because
 * there is no rate-limiting machinery anywhere in this repo. Without it,
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
 * anyone with a victim's address and would need rate-limiting machinery this
 * repo does not have. docs/03 §6c's existing mitigation — "no notification kind
 * fires at registration" — stays literally true.
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
    const live = await this.codes.findLive(userId, now);
    if (live && opts.respectFloor && now.getTime() - live.createdAt.getTime() < REISSUE_FLOOR_MS) {
      return 'too_soon';
    }
    if (live) {
      // Re-issuing retires the previous code, so exactly one is ever usable and
      // a code the user gave up on cannot be redeemed later by whoever else saw
      // it. The retirement is audited: a code that stopped working is a fact an
      // investigation may need (M13's reasoning).
      await this.codes.revokeLive(userId, now);
      await this.authEvents.insert({ userId, kind: 'email_verification.reissued' });
    }

    const code = readableCode();
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
      if (row !== null && row.user_id === userId) {
        // Only count an attempt against the caller's OWN code. Counting
        // somebody else's would let a signed-in attacker who guessed a digest
        // exhaust a victim's attempts and force them to re-issue.
        await this.codes.countAttempt(row.id);
      }
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
      await this.recordFailure(userId, sessionId);
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

function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/**
 * Reduce a code to the one form that gets hashed — M13's `canonicalCode`,
 * applied to this ceremony for the same reason and with the same proof.
 *
 * The alphabet excludes I, L, O and U so a code can survive being read off a
 * screen and typed, or read aloud. Redemption must therefore fold the same way
 * the mint did, or the very confusions the alphabet exists to survive
 * (lowercase, a typed "O" for zero, dropped grouping dashes) fail with the
 * uniform refusal and the user's only remedy is a fresh code — the exact
 * usability defect the M13 review found hiding behind a security property.
 *
 * IT CANNOT COLLIDE, and the argument is M13's: the fold is INJECTIVE ON
 * MINTED CODES. The `EV1-` prefix is constant, so it folds identically for
 * every code and distinguishes nothing; the 32-character body is drawn from an
 * alphabet excluding I, L, O and U, so within the body the fold is the
 * identity. Two different minted codes therefore differ in their bodies both
 * before and after folding. Case-folding costs no entropy either: the
 * generator only ever emits uppercase.
 */
export function canonicalCode(code: string): string {
  return code
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0');
}

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export const CODE_RANDOM_BYTES = 20;

/**
 * What a minted code folds to: the constant prefix plus the derived body, both
 * MEASURED rather than counted by hand, and pinned by a spec against a real
 * mint. Redemption checks this instead of trusting the request schema's own
 * length bound, which measures the raw submission.
 */
export const CANONICAL_CODE_LENGTH = canonicalCode('EV1-').length + (CODE_RANDOM_BYTES * 8) / 5;

/**
 * A 160-bit code in Crockford-style base32, grouped for reading: `EV1-K7MN-…`.
 *
 * THE WIDTH IS THE SECURITY PARAMETER, so it is derived, not asserted: 20 bytes
 * expanded at 5 bits per character is 32 characters exactly, and the assertion
 * below fails loudly rather than silently shipping a short code. M6's grantee
 * fingerprint carried 50 bits where its spec said 80, and M13's first link code
 * mapped one character per BYTE for a real width of 100; both were found by
 * looking at what a running system actually minted, so the derivation is
 * written down and tested rather than trusted.
 *
 * 160 bits is far more than a mailed short code needs — the attempt cap and
 * the 30-minute TTL are what actually bound guessing — but it is what the
 * repo's other ceremony uses, it costs the user nothing beyond a longer
 * copy-paste, and choosing a smaller number would mean defending it.
 */
function readableCode(): string {
  const bytes = randomBytes(CODE_RANDOM_BYTES);
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(acc >> bits) & 31];
    }
  }
  // 160 % 5 === 0, so nothing is left over; assert rather than assume.
  if (bits !== 0 || out.length !== (CODE_RANDOM_BYTES * 8) / 5) {
    throw new Error('verification code derivation is broken');
  }
  return `EV1-${(out.match(/.{1,4}/g) ?? []).join('-')}`;
}
