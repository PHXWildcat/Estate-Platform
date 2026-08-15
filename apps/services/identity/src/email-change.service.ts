import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { emailBlindIndex, normalizeEmail, type FieldCrypto } from '@estate/crypto';
import { NOTIFICATIONS, wasDelivered, type NotificationsPort } from '@estate/notifications-client';
import type { SessionContext } from '@estate/auth-guard';
import { AuthEventsRepo } from './auth-events.repo';
import type { IdentityConfig } from './config';
import { Db } from './db';
import { CLOCK, CONFIG, FIELD_CRYPTO, type Clock } from './di-tokens';
import { EmailChangeRepo, ChangeRaceError, MAX_CHANGE_ATTEMPTS } from './email-change.repo';
import { EmailVerificationRepo } from './email-verification.repo';
import { EventsService } from './events.service';
import { PasswordHasher } from './password';
import { PasswordResetRepo } from './password-reset.repo';
import { AddressAttemptBound } from './address-bound';
import { CHANGE_ADDRESS_BOUND } from './rate-bounds';
import { canonicalCode, canonicalLengthFor, readableCode, sha256 } from './readable-code';
import { SecondFactorGate } from './second-factor-gate';
import { SessionsRepo } from './sessions.repo';
import { UsersRepo } from './users.repo';

/** The mailed change code's prefix, in the M13/M14/M17 `<letters><version>-` shape. */
const EC_PREFIX = 'EC1-';
const CANONICAL_CODE_LENGTH = canonicalLengthFor(EC_PREFIX);

/** The field id `users.email_ct` is encrypted under — the SAME one register
 * uses, so staged ciphertext moves onto the live row byte-for-byte. */
const EMAIL_FIELD = 'users.email';

/** Thirty minutes: the mailbox channel's window (M14's number, M14's reason). */
export const CHANGE_TTL_MS = 30 * 60 * 1000;

/**
 * The floor between two mints for one account: M14's five minutes, because the
 * trust level matches (an AUTHENTICATED actor who has also just proved the
 * current password and, where one exists, a fresh second factor) — not
 * PR3's thirty, whose caller is anonymous. What the floor bounds is per-account
 * mail volume; per-DESTINATION volume is the address bound's job, and an
 * attacker who clears this route's gates owns the account already.
 */
export const CHANGE_FLOOR_MS = 5 * 60 * 1000;

function invalidCode(): BadRequestException {
  return new BadRequestException({ error: 'invalid_code' });
}

/**
 * THE ADDRESS CHANGE (M17 PR4) — verify-then-switch, and the ordering IS the
 * design.
 *
 * Login resolves users by `email_bidx`, so a change that stored an unproven
 * address would lock its owner out of LOGIN ITSELF the moment their sessions
 * lapsed: a typo'd new address must never reach `users` until a code mailed to
 * it comes back. The old address — and login, and every notification — keeps
 * working until the proof lands. This is also how the M14 forward commitment
 * ("clear `verified_at` in the same statement") is discharged one step
 * stronger: no unproven address ever reaches the delivery store at all, so the
 * bit is never cleared — it is stamped, by replacement, together with the
 * address it describes.
 *
 * ═══ THE GATE (the PR2 shape, verbatim) ═══
 *
 * Current password + conditional step-up. The password is the one thing a
 * stolen SESSION does not carry; the factor is the one thing a stolen PASSWORD
 * does not carry. Step-up is asked FIRST, before the password check, so an
 * account that needs a fresh factor is told so without this route becoming a
 * password oracle that costs nothing to query. §6m's own sentence is why this
 * route gets the full gate: control of the mailbox is control of the account,
 * so choosing the mailbox IS choosing the account's owner of last resort.
 *
 * ═══ WHAT COMPLETION SWEEPS (the §6m obligation) ═══
 *
 * Outstanding password-reset and address-verification codes die in the SAME
 * transaction as the switch: both were mailed to the mailbox being left, and a
 * reset code that outlived the address it was mailed to would let whoever
 * reads the OLD mailbox take the account after the owner moved away from it —
 * the exact capability the owner changed their address to escape.
 */
@Injectable()
export class EmailChangeService {
  constructor(
    private readonly users: UsersRepo,
    private readonly sessions: SessionsRepo,
    private readonly changes: EmailChangeRepo,
    private readonly resets: PasswordResetRepo,
    private readonly verifications: EmailVerificationRepo,
    private readonly authEvents: AuthEventsRepo,
    private readonly hasher: PasswordHasher,
    private readonly factors: SecondFactorGate,
    private readonly events: EventsService,
    private readonly db: Db,
    @Inject(FIELD_CRYPTO) private readonly fieldCrypto: FieldCrypto,
    @Inject(CONFIG) private readonly config: IdentityConfig,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(NOTIFICATIONS) private readonly notifications: NotificationsPort,
  ) {}

  /** Per-process, per-DESTINATION, in memory — `rate-bounds.ts` carries why
   * the ledger cannot hold this. Bounds mail volume at any one target address,
   * which the per-account floor cannot see when every request names a
   * different one. */
  private readonly addresses = new AddressAttemptBound(CHANGE_ADDRESS_BOUND, () => this.clock());

  /**
   * "Mail a challenge to this new address."
   *
   * SYNCHRONOUS HALF: the gate, the password, the floor and the destination
   * bound — every check whose answer the caller is entitled to. Then 202.
   *
   * DETACHED HALF (the controller's `void …catch`, pinned at the source): the
   * availability lookup, the encrypt, the stage and the send. The split is the
   * timing control — "is this address already registered" differs in KMS
   * calls, inserts and a carrier hand-off, so a caller measuring their own
   * request latency would otherwise read account existence out of it. Register
   * answers the same 201 either way for the same reason; a taken address here
   * is a mail that never arrives, exactly as a taken address there is a
   * registration that never happens.
   */
  async requestChange(
    userId: string,
    caller: Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'>,
    currentPassword: string,
    newEmail: string,
  ): Promise<{ staged: () => Promise<void> }> {
    const now = this.clock();
    // Step-up BEFORE the password check — the PR2 ordering, for its reason.
    await this.factors.assertMayAddFactor(userId, caller, now);

    const user = await this.users.findById(userId);
    if (!user || user.password_hash === null) {
      throw new BadRequestException({ error: 'invalid_credentials' });
    }
    if (!(await this.hasher.verifyPassword(user.password_hash, currentPassword))) {
      await this.authEvents.insert({ userId, kind: 'email_change.denied', decision: 'password' });
      await this.events.emailChangeDenied(userId);
      throw new BadRequestException({ error: 'invalid_credentials' });
    }

    const normalized = normalizeEmail(newEmail);
    const newBidx = emailBlindIndex(this.config.emailIndexKey, normalized);
    // Changing to the CURRENT address is refused openly: the caller is asking
    // about their own account, so there is nothing to keep uniform, and a
    // silent 202 would burn their floor on a no-op.
    if (newBidx.equals(user.email_bidx)) {
      throw new BadRequestException({ error: 'invalid_request' });
    }

    // The floor and the destination bound are both answerable openly — the
    // floor is about the CALLER's own account and the bound's refusal depends
    // on nothing the caller does not already know (their own request volume at
    // this address). `too_soon` rather than silence, because an authenticated
    // owner told nothing retries into the same wall.
    const lastMinted = await this.changes.lastMintedAt(userId);
    if (lastMinted !== null && now.getTime() - lastMinted.getTime() < CHANGE_FLOOR_MS) {
      throw new BadRequestException({ error: 'too_soon' });
    }
    if (this.addresses.exhausted(newBidx)) {
      await this.events.emailChangeThrottled();
      throw new BadRequestException({ error: 'too_soon' });
    }
    this.addresses.record(newBidx);

    // Everything past this line runs DETACHED (the controller owns the
    // detach): its work varies with whether the destination has an account,
    // and the caller's 202 must not.
    return {
      staged: async () => {
        await this.stageAndSend(userId, user.dek_id, normalized, newBidx, now);
      },
    };
  }

  private async stageAndSend(
    userId: string,
    dekId: string,
    normalized: string,
    newBidx: Buffer,
    now: Date,
  ): Promise<void> {
    // THE AVAILABILITY CHECK, silent by design. A taken address stages
    // nothing and mails nothing — the caller cannot tell this from a slow
    // mailbox, which is register's own posture for the identical question.
    // The unique index on `users.email_bidx` restates this at the switch, so
    // a register racing the ceremony window is refused there too.
    if ((await this.users.findByEmailBidx(newBidx)) !== null) {
      await this.authEvents.insert({
        userId,
        kind: 'email_change.refused',
        decision: 'address_taken',
      });
      return;
    }

    // RETIRE UNCONDITIONALLY — the predicate matches the index, never a clock
    // (the M14 review's worst finding: retire-only-when-usable wedged the live
    // slot forever after one ignored email).
    await this.changes.revokeLive(userId, now);

    // Encrypted as `users.email` under the account's LIVE key, so the switch
    // moves ciphertext without a decrypt. If the key rotates or is shredded
    // between now and redemption, the switch's dek_id predicate refuses.
    const { ciphertext } = await this.fieldCrypto.encryptField(userId, EMAIL_FIELD, normalized);

    const code = readableCode(EC_PREFIX);
    try {
      await this.changes.insert({
        userId,
        newEmailCt: ciphertext,
        newEmailBidx: newBidx,
        dekId,
        codeSha256: sha256(canonicalCode(code)),
        expiresAt: new Date(now.getTime() + CHANGE_TTL_MS),
      });
    } catch (err) {
      if (err instanceof ChangeRaceError) {
        return; // a concurrent request won; a change IS staged and mailed
      }
      throw err;
    }

    const outcome = await this.notifications.sendEmailChange({
      userId,
      kind: 'identity.email_change',
      code,
      email: normalized,
    });
    const delivered = wasDelivered(outcome);
    if (!delivered) {
      // Retire the code nobody holds. NOT to avoid a lockout, which is what
      // this comment used to claim and what the reset's twin claimed until it
      // was measured: `lastMintedAt` orders over ALL rows including revoked
      // ones, so retiring cannot shorten the re-issue floor, and the
      // unconditional retire before the mint already stops a stale code
      // blocking the next one. It is retired because a live change code that
      // reached no mailbox should not exist — and a carrier failure is the
      // case where the carrier may have taken the message before failing.
      await this.changes.revokeLive(userId, now);
    }
    await this.authEvents.insert({
      userId,
      kind: 'email_change.requested',
      decision: delivered ? 'delivered' : 'failed',
    });
    await this.events.emailChangeRequested(userId, delivered);
  }

  /**
   * Redeem the challenge and SWITCH.
   *
   * EVERY dead reason is one `invalid_code` — no live change, digest mismatch,
   * expired, spent, attempts exhausted, mis-shaped, key-rotated, or the
   * candidate address taken during the window. The caller is authenticated,
   * so unlike PR3 this uniformity is not about account enumeration; it is
   * about not handing whoever is GUESSING at an owner's pending change a
   * progress meter (the M13 §6g rule), and `address_taken` in particular
   * would leak another account's existence.
   *
   * ATOMICITY IS THE CONTROL: the spend, the switch, the code sweep and the
   * session revocation are ONE transaction. Then, in this order and each
   * outcome recorded: the notice to the OLD address (the store still resolves
   * it — that ordering is what makes the notice reach the only mailbox whose
   * reader can dispute a takeover), then the store replacement.
   */
  async completeChange(userId: string, sessionId: string, submitted: string): Promise<void> {
    const now = this.clock();
    const canonical = canonicalCode(submitted);
    if (canonical.length !== CANONICAL_CODE_LENGTH) {
      await this.refuse(userId, now);
    }

    const change = await this.changes.findLive(userId);
    if (
      !change ||
      change.attempts >= MAX_CHANGE_ATTEMPTS ||
      change.expires_at.getTime() <= now.getTime()
    ) {
      await this.refuse(userId, now);
      return;
    }
    if (!sha256(canonical).equals(change.code_sha256)) {
      // A wrong guess burns one attempt on the caller's own live change —
      // attributable because the selector is the user (the M14 round-2 fix,
      // designed in rather than retrofitted).
      await this.refuse(userId, now);
      return;
    }

    // Decrypt the candidate ONCE, before the transaction: the recipient
    // replacement after commit needs the plaintext, and decrypting inside the
    // transaction would hold the row lock across a KMS round trip. Audited by
    // FieldCrypto's sink like every Zone B decrypt.
    const newAddress = (
      await this.fieldCrypto.decryptField({
        userId,
        dekId: change.dek_id,
        field: EMAIL_FIELD,
        ciphertext: change.new_email_ct,
        actorId: userId,
        actorType: 'user',
        purpose: 'email_change',
      })
    ).toString('utf8');

    let revoked: string[] = [];
    try {
      revoked = await this.db.withTransaction(userId, async (tx) => {
        if (!(await this.changes.markCompleted(tx, change.id, now))) {
          throw invalidCode();
        }
        // dek_id is restated inside the UPDATE: a key rotated or shredded
        // since the mint means this ciphertext no longer belongs on the row.
        if (
          !(await this.users.updateEmail(tx, userId, {
            emailCt: change.new_email_ct,
            emailBidx: change.new_email_bidx,
            dekId: change.dek_id,
          }))
        ) {
          throw invalidCode();
        }
        // THE SWEEP (§6m's obligation): codes mailed to the just-left mailbox
        // die with the address, in the same commit. A PR1- reset code
        // surviving this would hand whoever reads the OLD mailbox the account
        // the owner just moved away from.
        await this.resets.revokeLive(userId, now, tx);
        await this.verifications.revokeLive(userId, now, tx);
        // Every other session: the PR2 posture. The attacker's sessions and
        // the owner's other devices cannot be told apart, so all but the one
        // that just proved password + factor + mailbox.
        return this.sessions.revokeAllForUserExcept(tx, userId, sessionId, 'email_changed', now);
      });
    } catch (err) {
      // The candidate address was registered by someone else during the
      // ceremony window: ux_users_email refused the switch. Uniform refusal —
      // "taken" would leak the other account — and an attempt is NOT burned
      // (the code was right; the world changed).
      if (isUniqueViolation(err)) {
        await this.refuse(userId, now, { countAttempt: false });
        return;
      }
      throw err;
    }

    // THE NOTICE TO THE OLD ADDRESS, deliberately before the replacement: the
    // store still resolves the address being left, which is the only mailbox
    // whose reader can dispute a takeover. A failure is recorded and does not
    // undo the change (M9: sends never roll back state).
    const notice = await this.notifications.sendAccountSecurity({
      userId,
      kind: 'identity.email_changed',
    });
    const oldNotified = wasDelivered(notice);

    // THE REPLACEMENT: repoint and vouch in one statement — the address was
    // proved by the redemption seconds ago. A failure self-heals at the next
    // login (which can only carry the NEW address; the old bidx no longer
    // resolves), and is recorded so an operator can re-drive it.
    const replaced = await this.notifications.replaceRecipient({ userId, email: newAddress });

    await this.authEvents.insert({ userId, kind: 'email_change.completed' });
    await this.events.emailChangeCompleted(userId, {
      revokedSessions: revoked.length,
      oldNotified,
      recipientReplaced: replaced.ok,
    });
  }

  /**
   * Withdraw the pending change — one ungated action on the caller's own
   * account (the M6 rule: the protective action must never be harder than the
   * permissive one; minting is the gated half).
   */
  async cancelChange(userId: string): Promise<void> {
    const now = this.clock();
    if (await this.changes.revokeLive(userId, now)) {
      await this.authEvents.insert({ userId, kind: 'email_change.cancelled' });
      await this.events.emailChangeCancelled(userId);
    }
  }

  /**
   * One refusal for every dead reason, burning an attempt on the caller's own
   * live change unless the failure was the world's rather than the guess's.
   * The audit event carries no reason (the M14 PR1 rule — a trail that named
   * which refusal fired would be the progress meter the wire withholds).
   */
  private async refuse(
    userId: string,
    now: Date,
    opts: { countAttempt: boolean } = { countAttempt: true },
  ): Promise<never> {
    if (opts.countAttempt) {
      await this.changes.countAttempt(userId, now);
    }
    await this.authEvents.insert({ userId, kind: 'email_change.failed' });
    await this.events.emailChangeFailed(userId);
    throw invalidCode();
  }
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505';
}
