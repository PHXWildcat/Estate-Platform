import { ConflictException, Inject, Injectable } from '@nestjs/common';
import { Db } from './db';
import { CLOCK, type Clock } from './di-tokens';
import { ErasureRepo, type ErasureRequestRow } from './erasure.repo';
import { EventsService } from './events.service';

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

/** What the surface renders. `null` means no request is live. */
export interface ErasureState {
  status: 'pending';
  requestedAt: string;
}

function toState(row: ErasureRequestRow): ErasureState {
  return { status: 'pending', requestedAt: row.requested_at.toISOString() };
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
   * normal answer, not an error, and it returns the same shape as a successful
   * cancel so a client cannot tell a race from a no-op and does not need to.
   */
  async cancel(userId: string, sessionId: string | null): Promise<null> {
    const cancelled = await this.db.withTransaction(userId, (tx) =>
      this.repo.cancel(tx, userId, this.clock()),
    );
    if (cancelled !== null) {
      await this.events.accountErasureCancelled(userId, sessionId, cancelled.id);
    }
    return null;
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
