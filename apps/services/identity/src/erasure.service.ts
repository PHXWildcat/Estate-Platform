import { randomUUID } from 'node:crypto';
import { ConflictException, Inject, Injectable } from '@nestjs/common';
import { ERASURE_DOMAINS, type ErasureRequestStatus } from '@estate/contracts';
import { emailBlindIndex, type FieldCrypto } from '@estate/crypto';
import type { IdentityConfig } from './config';
import { Db } from './db';
import { EmailChangeRepo } from './email-change.repo';
import { CLOCK, CONFIG, DEK_REPOSITORY, FIELD_CRYPTO, type Clock } from './di-tokens';
import type { PgDekRepository } from './dek.repository';
import { ErasureRepo, type ErasureRequestRow } from './erasure.repo';
import { EventsService } from './events.service';
import { SessionsRepo } from './sessions.repo';
import { UsersRepo } from './users.repo';

/**
 * This service's own domain in the erasure ledger. Identity is the one domain
 * M25 can reach: it holds its own DEK in its own cluster, so its leg needs no
 * transport and no second service to be deployed first.
 */
const THIS_DOMAIN = 'identity' as const;

/**
 * Reserved domain for the address an erased row is re-indexed to. `.invalid` is
 * reserved by RFC 2606 and can never resolve or be registered, so the value can
 * never collide with a real user's index.
 */
const ERASED_ADDRESS_DOMAIN = 'erased.invalid';

/**
 * The actor recorded on the driver's own transactions.
 *
 * EMPTY, WHICH THE CAPTURE TRIGGER TURNS INTO A NULL `actor_id` — every
 * `*_capture_version` body reads `NULLIF(current_setting('app.actor_id', true),
 * '')::uuid`. That is the accurate statement: no person performed these writes.
 * Putting the owner's id here would read, in the version shadow, as the owner
 * having closed their own account minutes ago, when what they actually did was
 * ask days earlier. The join between the two is `requestId` on the audit trail,
 * which is why every event in this leg carries it.
 */
const DRIVER_ACTOR = '';

/**
 * Account statuses from which an owner may REQUEST erasure. An allowlist, not
 * a denylist: a status added to the `users` CHECK later is refused until
 * somebody decides it should not be, which is the direction that fails safe for
 * the most irreversible verb in the product.
 *
 * ONLY ONE REFUSAL IS ACTUALLY REACHABLE, and knowing which changes what the
 * copy has to say. `SessionsRepo.findLiveByAccessHash` resolves a session only
 * while the account is 'active' or 'deceased_pending', so a caller holding a
 * live session is necessarily one of those two — 'locked', 'suspended',
 * 'settlement' and 'closed' cannot reach this code with a session at all. The
 * allowlist still refuses them (deny by default costs nothing here), but
 * `deceased_pending` is the refusal a real person will see, and it is the one
 * that gets a remedy rather than a generic message.
 */
export const ERASURE_PERMITTED_STATUSES: readonly string[] = ['active'];

/**
 * What the surface renders. `null` means no request is live.
 *
 * THE STATUS IS CARRIED, not assumed. PR2 could hard-code 'pending' because it
 * was the only live state; PR3 adds 'executing', and the difference is the one
 * a user most needs to see — 'pending' can still be withdrawn, 'executing'
 * cannot. A surface that rendered both as "requested" would offer a cancel
 * button that silently does nothing.
 */
export interface ErasureState {
  status: ErasureRequestStatus;
  requestedAt: string;
}

function toState(row: ErasureRequestRow): ErasureState {
  return { status: row.status, requestedAt: row.requested_at.toISOString() };
}

/**
 * The DECISION half of account erasure (M25 PR2, docs/04). Owner-initiated and
 * step-up gated at the route; this class decides whether a request may exist
 * and lets the owner withdraw it. It destroys nothing — `destroyDek` still has
 * no production caller, and the fan-out is PR3.
 *
 * THE PROTECTIVE VERB IS THE UNGATED ONE, which is the repo's rule wearing an
 * unfamiliar shape. Usually the permissive action is gated and the protective
 * one is free (grant vs revoke); here the permissive action IS the destructive
 * one, so the asymmetry inverts: requesting erasure needs a fresh step-up,
 * cancelling needs nothing but the session. A cancel that were harder than a
 * request would mean an owner who changed their mind — or whose session was
 * briefly stolen — could arm the most irreversible process in the product and
 * then be made to prove themselves before disarming it.
 */
@Injectable()
export class ErasureService {
  constructor(
    private readonly db: Db,
    private readonly repo: ErasureRepo,
    private readonly events: EventsService,
    private readonly users: UsersRepo,
    private readonly emailChanges: EmailChangeRepo,
    private readonly sessions: SessionsRepo,
    @Inject(FIELD_CRYPTO) private readonly crypto: FieldCrypto,
    @Inject(DEK_REPOSITORY) private readonly deks: PgDekRepository,
    @Inject(CONFIG) private readonly config: IdentityConfig,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /**
   * Record an erasure request. Idempotent: a second request while one is live
   * answers with the SAME request rather than a conflict, because a user who
   * presses the button twice means the thing they meant the first time.
   */
  async request(userId: string, sessionId: string | null): Promise<ErasureState> {
    const { row, refusal } = await this.db.withTransaction(userId, async (tx) => {
      const inserted = await this.repo.insertIfPermitted(
        tx,
        userId,
        sessionId,
        ERASURE_PERMITTED_STATUSES,
      );
      if (inserted !== null) {
        return { row: inserted, refusal: null };
      }
      // Zero rows means REFUSED or ALREADY REQUESTED, and the count cannot say
      // which. Re-read inside the same transaction rather than guessing.
      const live = await this.repo.findLive(tx, userId);
      if (live !== null) {
        return { row: live, refusal: null };
      }
      return { row: null, refusal: await this.repo.statusOf(tx, userId) };
    });

    if (row === null) {
      throw new ConflictException({ error: refusalToken(refusal) });
    }
    await this.events.accountErasureRequested(userId, sessionId, row.id);
    return toState(row);
  }

  /**
   * Withdraw the live request. Safe to press twice: nothing to cancel is a
   * normal answer and not an error.
   *
   * IT ANSWERS WHAT IS STILL LIVE, which PR2 did not have to. Then 'pending'
   * was the only live state and null was the whole truth. Now a cancel can fail
   * for a reason the owner must be told about — the driver has claimed the
   * request and is destroying keys — and "there was nothing to cancel" and "it
   * is too late" are two outcomes with different remedies. Returning the
   * remaining live request rather than a second error token keeps the
   * protective verb ungated, unfailing and honest at once: null means nothing
   * is outstanding, a state means it still is.
   */
  async cancel(userId: string, sessionId: string | null): Promise<ErasureState | null> {
    const { cancelled, remaining } = await this.db.withTransaction(userId, async (tx) => {
      const row = await this.repo.cancel(tx, userId, this.clock());
      if (row !== null) {
        return { cancelled: row, remaining: null };
      }
      // Nothing moved. Either there was no request, or it is already
      // executing — re-read INSIDE the transaction rather than inferring a
      // reason from an affected-row count.
      return { cancelled: null, remaining: await this.repo.findLive(tx, userId) };
    });

    if (cancelled !== null) {
      await this.events.accountErasureCancelled(userId, sessionId, cancelled.id);
      return null;
    }
    return remaining === null ? null : toState(remaining);
  }

  /**
   * THE DESTROY LEG (M25 PR3). Executes every request whose grace period has
   * lapsed. Returns how many it carried through identity's domain.
   *
   * ONE REQUEST PER CLAIM, IN A LOOP, rather than a batch. A batch would hold
   * one transaction open across n crypto-shreds, so a failure on the last would
   * roll back the ledger for all of them while the destroyed keys stayed
   * destroyed — a rollback that unwinds the record and not the act is worse
   * than no transaction at all.
   *
   * IDEMPOTENT AND RESUMABLE BY CONSTRUCTION, because the steps below span four
   * writes that cannot share a transaction (one of them is a KMS-adjacent key
   * destruction). Every step re-reads the fact it needs instead of trusting the
   * previous step to have happened, so a process killed anywhere in the middle
   * is finished by the next tick rather than left half done with nothing saying
   * where it stopped.
   */
  async runDueErasures(now: Date): Promise<number> {
    const cutoff = new Date(now.getTime() - this.config.erasureGracePeriodMs);
    // EVERY REQUEST THIS SWEEP HAS ALREADY WORKED.
    //
    // The loop's termination rests on a claim predicate going false once this
    // domain reports, and PR4 found how easily that reasoning breaks: the first
    // draft of the resume arm asked "does this request have unfinished work",
    // which is PERMANENTLY TRUE while seven domains have no transport, and the
    // sweep spun forever re-claiming the same row. The predicate is fixed —
    // it asks about THIS domain — and this set is the backstop, because the
    // failure mode of getting it wrong again is a driver that never returns,
    // which no assertion can catch and no test can name. A second sighting is
    // impossible if the predicate is right, so this converts a future
    // regression from a hang into a value a test can read.
    const worked = new Set<string>();
    let carried = 0;
    for (;;) {
      const claimed = await this.db.withTransaction(DRIVER_ACTOR, async (tx) => {
        const request = await this.repo.claimDue(
          tx,
          cutoff,
          now,
          ERASURE_PERMITTED_STATUSES,
          THIS_DOMAIN,
        );
        if (request !== null) {
          // Seeded inside the CLAIM transaction. A crash between the two would
          // leave a request executing with an empty ledger, which
          // `completeIfAllDone` would read as "every domain is done" — and
          // which the resume arm, keyed on a ledger row, could never re-claim.
          await this.repo.seedDomains(tx, request.id, ERASURE_DOMAINS);
        }
        return request;
      });
      if (claimed === null) {
        return carried;
      }
      if (worked.has(claimed.id)) {
        // Re-claimed inside one sweep: the predicate has stopped narrowing.
        // Stop rather than spin — the requests already carried are done and
        // durable, and the next tick will find whatever is genuinely left.
        return carried;
      }
      worked.add(claimed.id);
      await this.executeIdentityDomain(claimed, now);
      carried += 1;
    }
  }

  /**
   * Identity's own domain of one erasure.
   *
   * THE ORDER IS THE SECURITY PROPERTY, and it is the documented exception to
   * "the step that cannot be undone runs last" — here the REVERSIBLE steps are
   * the ones that strand state, so they run first:
   *
   *   1. Close the account and unlink the address. Until this lands, a live
   *      session can still act.
   *   2. Revoke every session. Until this lands, a request already in flight
   *      can still act.
   *   3. Unlink every address this user ever STAGED (M25 PR5). Same category as
   *      step 1's `email_bidx` — an HMAC under a service-wide key, so the shred
   *      in step 4 does not reach it — but in `email_changes`, and it runs
   *      after step 1 rather than inside it so that the ineligibility hand-back
   *      above still leaves NOTHING destroyed.
   *   4. Destroy the DEK.
   *
   * REVERSING 1-3 AND 4 WOULD SILENTLY UN-ERASE THE ACCOUNT. `getOrCreateDek`
   * MINTS a key when the user has no active one — that is correct behaviour for
   * every other caller and a disaster for this one. Destroy first and any
   * surviving session that touches an encrypted field gives the account a
   * brand-new DEK, so the row is live again, the ciphertext written after it is
   * readable, and the audit trail says the erasure succeeded. Closing and
   * revoking first is what makes step 4 the last thing that can happen.
   *
   * NOTHING HERE ROLLS BACK, so each step is written to be safe to repeat and
   * each is guarded by a re-read of the fact it changes rather than by a flag.
   */
  private async executeIdentityDomain(request: ErasureRequestRow, now: Date): Promise<void> {
    const user = await this.users.findById(request.user_id);
    if (user === null) {
      // The row is gone entirely — nothing this service can erase, and nothing
      // it should invent. Leave the claim so a human sees an erasure that
      // stopped; a request that quietly completed against a missing user is
      // exactly the record that would be believed later.
      return;
    }

    if (user.status !== 'closed') {
      const closed = await this.db.withTransaction(DRIVER_ACTOR, (tx) =>
        this.users.closeAndUnlinkEmail(
          tx,
          request.user_id,
          ERASURE_PERMITTED_STATUSES,
          this.erasedEmailIndex(),
        ),
      );
      if (closed === null) {
        // The account became ineligible between the claim and this write — a
        // death report or a settlement lock landed in the gap. Nothing has been
        // destroyed, so hand the claim back rather than wedging the request:
        // on 'pending' the owner can still cancel it and the next tick retries.
        await this.db.withTransaction(DRIVER_ACTOR, (tx) => this.repo.releaseClaim(tx, request.id));
        return;
      }
      await this.events.userClosedForErasure(request.user_id, user.status, request.id);

      const revoked = await this.sessions.revokeAllForUser(request.user_id, 'account_erased', now);
      await this.events.sessionsRevokedForErasure(request.user_id, revoked.length, request.id);
    }

    // UNCONDITIONAL, NOT INSIDE THE CLOSE BLOCK ABOVE. A request that was
    // claimed, closed and then interrupted resumes here with `status` already
    // 'closed', so anything hung off the close guard is skipped on exactly the
    // path the resume arm exists to serve — the same shape of unreachable
    // idempotence M25 PR4 found in PR3's own leg. Repeating it is safe: each
    // run re-indexes to another address nobody holds, and `revoked_at` is
    // COALESCEd rather than overwritten.
    await this.db.withTransaction(DRIVER_ACTOR, (tx) =>
      this.emailChanges.unlinkAllForErasure(tx, request.user_id, this.erasedEmailIndex(), now),
    );

    // The irreversible step, guarded by the fact rather than by a flag: a
    // second run finds `destroyedAt` set and emits nothing, so a retry cannot
    // reset the timestamp or double-file the event.
    const dek = await this.deks.findById(user.dek_id);
    if (dek !== null && dek.destroyedAt === null) {
      await this.crypto.destroyDek(user.dek_id);
      await this.events.dekDestroyed(request.user_id, user.dek_id, request.id);
    }

    await this.db.withTransaction(DRIVER_ACTOR, async (tx) => {
      await this.repo.markDomainDone(tx, request.id, THIS_DOMAIN);
      await this.repo.completeIfAllDone(tx, request.id, now);
    });
  }

  /**
   * The value that replaces a live blind index — `users.email_bidx`, and since
   * M25 PR5 `email_changes.new_email_bidx`.
   *
   * A REAL BLIND INDEX OF AN ADDRESS NOBODY HOLDS, not random bytes. Building
   * it through `emailBlindIndex` means the width, the HMAC key and the purpose
   * label can never drift from the live ones — a replacement of the wrong shape
   * would make every erased row identifiable by its column alone, which is a
   * worse leak than the lookup it removes. The address is a fresh uuid under a
   * reserved TLD, so it is unlinkable to the erased owner, unlinkable to every
   * other erased row, and cannot collide with `ux_users_email`.
   */
  private erasedEmailIndex(): Buffer {
    return emailBlindIndex(this.config.emailIndexKey, `${randomUUID()}@${ERASED_ADDRESS_DOMAIN}`);
  }

  /** The caller's live request, or null. */
  async get(userId: string): Promise<ErasureState | null> {
    const live = await this.repo.findLive(this.db, userId);
    return live === null ? null : toState(live);
  }
}

/**
 * TWO REFUSALS, TWO TOKENS, because they need different things from the reader.
 *
 * A living owner who has been reported dead is in the one state where refusing
 * erasure is a CONTROL FIRING rather than an outage, and the remedy is theirs to
 * take: sign in, void the case, come back. Collapsing that into a generic
 * refusal would tell somebody whose account is being taken from them that the
 * product is broken. Everything else is unreachable with a live session today
 * and gets the generic token — stated rather than merged, so the day a new
 * status becomes session-bearing the copy is wrong loudly instead of quietly.
 */
function refusalToken(status: string | null): string {
  return status === 'deceased_pending' ? 'open_death_report' : 'erasure_not_permitted';
}
