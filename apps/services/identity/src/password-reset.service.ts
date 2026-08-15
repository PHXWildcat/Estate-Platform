import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { emailBlindIndex, normalizeEmail } from '@estate/crypto';
import { NOTIFICATIONS, wasDelivered, type NotificationsPort } from '@estate/notifications-client';
import { AuthEventsRepo } from './auth-events.repo';
import type { IdentityConfig } from './config';
import { Db } from './db';
import { CLOCK, CONFIG, type Clock } from './di-tokens';
import { EventsService } from './events.service';
import { PasswordHasher } from './password';
import { PasswordResetRepo, ResetRaceError } from './password-reset.repo';
import { AddressAttemptBound } from './address-bound';
import { RESET_ADDRESS_BOUND } from './rate-bounds';
import { canonicalCode, canonicalLengthFor, readableCode, sha256 } from './readable-code';
import { SessionsRepo } from './sessions.repo';
import { UsersRepo } from './users.repo';

/** The mailed reset code's prefix, in the M13/M14 `<letters><version>-` shape. */
const PR_PREFIX = 'PR1-';
const CANONICAL_CODE_LENGTH = canonicalLengthFor(PR_PREFIX);

/**
 * THIRTY MINUTES, from the delivery channel rather than from a policy.
 *
 * The same number as M14's verification code and for the same reason: it
 * travels by mailbox, so the window has to cover somebody noticing a mail and
 * acting on it, and no longer. It is not M13's days (that code travels by phone
 * call) and not M15's sixty seconds (no human ever sees that one).
 */
export const RESET_TTL_MS = 30 * 60 * 1000;

/**
 * The floor between two mints for one account.
 *
 * Wider than M14's five minutes, deliberately: that route is AUTHENTICATED and
 * mails the caller their own address, while this one is reachable by anyone who
 * can type an address they do not own. The per-address bound in
 * `rate-bounds.ts` is the primary defence; this is the durable per-account one
 * behind it, and it is what stops a caller who evades the in-memory bound from
 * driving mail at a stranger's inbox at more than two an hour.
 */
export const RESET_FLOOR_MS = 30 * 60 * 1000;

function invalidCode(): BadRequestException {
  return new BadRequestException({ error: 'invalid_code' });
}

/**
 * PASSWORD RESET (M17 PR3) — the ceremony for a password nobody can present.
 *
 * ═══ WHAT IT MINTS: NOTHING ═══
 *
 * Redemption sets the password and returns no tokens, no session, no step-up.
 * The user signs in afterwards with what they just chose.
 *
 * That is the whole answer to "does redeeming a reset code grant step-up?", and
 * it is structural rather than a rule somebody has to keep: there is no session
 * to withhold anything from. The M15 PR4 review is why it matters — an
 * unauthenticated redeem route that granted step-up let a stolen 60-second
 * handoff code reach `POST /v1/vault/reset`, which is gated on step-up ALONE,
 * and crypto-shred a Zone A vault. A reset code that granted step-up would be
 * that same primitive delivered by email, to a longer-lived code.
 *
 * It also avoids a trap the two-step shape walks into. `AllowSessionAudiences`
 * unconditionally PREPENDS `account`, and identity binds no service-wide
 * audience list, so a fourth `recovery` audience could not be made exclusive on
 * an identity route: a completion route admitting it would ALSO be reachable by
 * every ordinary account session — a set-a-new-password-without-the-current-one
 * route behind any stolen bearer, which is strictly worse than what this
 * milestone exists to fix.
 *
 * ═══ WHAT IT DOES NOT RECOVER ═══
 *
 * THE VAULT. Zone A's master key derives from the vault password and the Secret
 * Key under 2SKD and has no relationship to the account password, so nothing
 * here re-keys, re-wraps or opens anything in Zone A. Telling somebody they
 * have recovered something they have not is the worst outcome available on this
 * path, so the surface says it too.
 *
 * ═══ THE SECOND FACTOR ═══
 *
 * A reset requires the mailed code and NOTHING ELSE, even for an account that
 * holds a verified TOTP or passkey. That is a decision taken deliberately
 * (docs/03 §6m) and its consequence is stated there rather than softened: for
 * such an account, control of the mailbox is control of the account, so a
 * verified second factor does not protect against mailbox compromise. What
 * bounds the damage is that the vault is untouched, every session is revoked so
 * the real owner is signed out and notices, and the whole sequence is on the
 * audit trail.
 */
@Injectable()
export class PasswordResetService {
  constructor(
    private readonly users: UsersRepo,
    private readonly sessions: SessionsRepo,
    private readonly codes: PasswordResetRepo,
    private readonly authEvents: AuthEventsRepo,
    private readonly hasher: PasswordHasher,
    private readonly events: EventsService,
    private readonly db: Db,
    @Inject(CONFIG) private readonly config: IdentityConfig,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(NOTIFICATIONS) private readonly notifications: NotificationsPort,
  ) {}

  /**
   * Per-process, per-address, in memory — `rate-bounds.ts` carries why the
   * ledger cannot hold this (an append-only table with no `dek_id` must not
   * record a correlatable identifier for people who have no account here).
   */
  private readonly addresses = new AddressAttemptBound(RESET_ADDRESS_BOUND, () => this.clock());

  /**
   * "Send me a reset code."
   *
   * RESOLVES TO NOTHING A CALLER CAN LEARN FROM, and the ROUTE does not await
   * it — the detach lives in the controller, which is M14's shape
   * (`ensureVerificationRequested` is awaitable and the login hook wraps it
   * with `void`), not an accident of refactoring. The first version detached
   * HERE, returning `void` so awaiting the work was inexpressible — and the
   * cost surfaced immediately: the only way any test could drive this path was
   * a bare sleep racing real Postgres round trips, which flaked in CI on the
   * second run (the M8 PR4 determinism contract, violated by the test the
   * fire-and-forget forced). An awaitable method keeps every layer
   * deterministic; the timing property moves to the controller, where a
   * source-level pin holds it (a runtime test cannot tell a fast await from no
   * await — the M17 PR1 ordering-pin rule).
   *
   * If the ROUTE awaited this, an existing account would answer measurably
   * later than a stranger's address — the account-existence oracle register's
   * own docstring records as still open. The caller is never told whether a
   * mail was sent, refused by the floor, or had nowhere to go; a delivery
   * failure is visible in the trail and the send log, never in the response.
   */
  async requestReset(email: string): Promise<void> {
    const normalized = normalizeEmail(email);
    const emailBidx = emailBlindIndex(this.config.emailIndexKey, normalized);
    // THE ADDRESS BOUND, and it is the primary one on this route. The
    // per-account floor inside `mintAndSend` can only be evaluated once an
    // address resolves to a user, so it sees nothing at all for an address with
    // no account — which is most of what an abuser submits. This one counts
    // every attempt, existence-independent, before any work.
    //
    // The refusal is SILENT: the route answers 202 either way, so a dropped
    // request is indistinguishable from a delivered one. Recording it is the
    // audit trail's job, not the response's.
    if (this.addresses.exhausted(emailBidx)) {
      void this.events.passwordResetThrottled();
      return;
    }
    this.addresses.record(emailBidx);
    await this.mintAndSend(emailBidx);
  }

  private async mintAndSend(emailBidx: Buffer): Promise<void> {
    const user = await this.users.findByEmailBidx(emailBidx);
    if (!user) {
      // No account, and deliberately no trace: a `login.failed`-style row keyed
      // on nothing would be a record about a person who has no relationship
      // with this platform, and the per-address bound above already counts the
      // attempt.
      return;
    }
    // The SAME allowlist the session lookups and the password change use.
    // `deceased_pending` is permitted because docs/03 §5.1's rescue path is the
    // living owner signing in and voiding the case; `settlement` is refused
    // because handing a working credential to whoever controls a decedent's
    // mailbox is precisely the §5.1 fraud this platform is built around.
    if (user.status !== 'active' && user.status !== 'deceased_pending') {
      await this.authEvents.insert({
        userId: user.id,
        kind: 'password.reset_refused',
        decision: 'account_status',
      });
      return;
    }

    const now = this.clock();
    const lastMinted = await this.codes.lastMintedAt(user.id);
    if (lastMinted !== null && now.getTime() - lastMinted.getTime() < RESET_FLOOR_MS) {
      return;
    }

    // RETIRE UNCONDITIONALLY. `revokeLive`'s predicate matches the partial
    // unique index, which cannot carry an expiry clause — retiring only when a
    // usable code exists is what made M14's ceremony answer `too_soon` forever
    // after one ignored email. Here that would mean an account whose owner
    // ignored a single reset mail could never be recovered.
    await this.codes.revokeLive(user.id, now);

    const code = readableCode(PR_PREFIX);
    try {
      await this.codes.insert({
        userId: user.id,
        // The CANONICAL form is hashed, so redemption accepts the code as a
        // human actually retypes it — lowercase, grouping dashes dropped, an
        // O typed for a zero.
        codeSha256: sha256(canonicalCode(code)),
        expiresAt: new Date(now.getTime() + RESET_TTL_MS),
      });
    } catch (err) {
      if (err instanceof ResetRaceError) {
        return; // a concurrent request won; a code IS live and has been mailed
      }
      throw err;
    }

    const outcome = await this.notifications.sendPasswordReset({
      userId: user.id,
      kind: 'identity.password_reset',
      code,
    });
    // `wasDelivered`, NOT `outcome.accepted`: the latter is the union's
    // discriminant and says only that a healthy notifications service answered.
    // `no_recipient` (M9's recipient feed is fire-and-forget, so a registration
    // during a notifications outage leaves no row — and that user is precisely
    // the one who later cannot sign in) and `carrier_failure` both answer
    // `accepted: true, delivered: false`, which this read scored as a delivery.
    const delivered = wasDelivered(outcome);
    if (!delivered) {
      // Retire the code nobody holds. NOT because it would otherwise lock the
      // account out — `lastMintedAt` counts revoked rows, so retiring cannot
      // shorten the re-issue floor, and the unconditional retire above already
      // stops a stale code blocking the next mint. It is retired because a
      // live reset code that reached no mailbox should not exist, and
      // `carrier_failure` is the case where the carrier may have taken the
      // message before failing.
      await this.codes.revokeLive(user.id, now);
    }
    await this.authEvents.insert({
      userId: user.id,
      kind: 'password.reset_requested',
      decision: delivered ? 'delivered' : 'failed',
    });
    await this.events.passwordResetRequested(user.id, delivered);
  }

  /**
   * Redeem a code and set the new password.
   *
   * EVERY FAILURE IS ONE `invalid_code` — unknown, mis-shaped, expired, already
   * spent, revoked, raced, or belonging to an account whose status no longer
   * permits it. Distinguishing them would tell whoever holds a guess that it
   * named something real (the M13 §6g rule), and here it would additionally
   * leak account state to an unauthenticated caller.
   *
   * ATOMICITY IS THE CONTROL. Spending the code, writing the hash and revoking
   * the sessions are ONE transaction: a spend without the write burns the
   * user's only recovery code, a write without the spend leaves the code
   * REPLAYABLE by whoever read that mailbox, and a write without the revocation
   * leaves every session minted under the old password live.
   */
  async completeReset(submitted: string, newPassword: string): Promise<void> {
    const canonical = canonicalCode(submitted);
    // Measured on the CANONICAL form against a length DERIVED from the mint —
    // the M13 round-3 finding, where a raw `min(8)` was satisfied by separators
    // alone. Refused before any lookup, with the same token as everything else.
    if (canonical.length !== CANONICAL_CODE_LENGTH) {
      await this.refuse();
    }

    const row = await this.codes.findByCode(sha256(canonical));
    const now = this.clock();
    if (
      !row ||
      row.revoked_at !== null ||
      row.redeemed_at !== null ||
      row.expires_at.getTime() <= now.getTime()
    ) {
      await this.refuse();
      return;
    }

    const newHash = await this.hasher.hashPassword(newPassword);
    const revoked = await this.db.withTransaction(row.user_id, async (tx) => {
      // The spend restates its own preconditions, so two concurrent
      // redemptions of one code produce exactly one success and the loser
      // rolls back.
      if (!(await this.codes.markRedeemed(tx, row.id, now))) {
        throw invalidCode();
      }
      // The status allowlist rides the UPDATE. `findByCode` carries no status
      // predicate and there is no session guard above this route, so a check
      // anywhere else would be a check-then-act on the one route that hands out
      // a working credential for an account somebody else may be settling.
      if (!(await this.users.updatePasswordHash(tx, row.user_id, newHash))) {
        throw invalidCode();
      }
      // EVERY session, including any the attacker minted. There is no caller
      // session to preserve here — that is what distinguishes this from the
      // password CHANGE, which keeps the one that just proved the old password.
      return this.sessions.revokeAllForUserExcept(
        tx,
        row.user_id,
        NO_SESSION,
        'password_reset',
        now,
      );
    });

    // Deliberately NOT `stepup.granted`: that literal is hardcoded in the
    // owner-liveness interlock, so emitting it would silently void an open
    // §5.1 death case as a side effect of a reset — and hand that capability to
    // whoever controls the mailbox.
    await this.authEvents.insert({ userId: row.user_id, kind: 'password.reset_completed' });
    const notified = await this.notifications.sendAccountSecurity({
      userId: row.user_id,
      kind: 'identity.password_changed',
    });
    await this.events.passwordReset(row.user_id, revoked.length, wasDelivered(notified));
  }

  /**
   * The uniform refusal, with an audit event carrying NO actor and NO reason.
   *
   * A trail that named which failure applied would re-create through the audit
   * stream exactly the oracle the uniform answer removes from the wire — the
   * M14 PR1 rule, and it binds harder here because the caller is
   * unauthenticated and the subject may be somebody who does not exist.
   */
  private async refuse(): Promise<never> {
    await this.events.passwordResetFailed();
    throw invalidCode();
  }
}

/**
 * The sentinel "no session is exempt" id for the reset's bulk revocation.
 *
 * `revokeAllForUserExcept` is reused rather than widening `revokeAllForUser`,
 * whose one production caller is the settlement lock and whose comment reserves
 * it for that and for theft response. Passing an id no session can have makes
 * the exemption empty, so the reset revokes everything — which is what it must
 * do, since the caller holds no session to keep.
 */
const NO_SESSION = '00000000-0000-0000-0000-000000000000';
