import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuthEventsRepo } from './auth-events.repo';
import { EventsService } from './events.service';
import { SessionsRepo } from './sessions.repo';
import { UsersRepo } from './users.repo';

/** The states the settlement service may put an account into, and from where. */
const ALLOWED_TRANSITIONS: Record<SettlementLockState, readonly string[]> = {
  // Review approved a credible death report — waiting period begins.
  deceased_pending: ['active'],
  // Case verified: the account is estate-administered from here on.
  settlement: ['deceased_pending'],
  // Case voided/rejected while pending — the living owner gets their account back.
  active: ['deceased_pending'],
};

export type SettlementLockState = 'deceased_pending' | 'settlement' | 'active';

export interface LivenessResult {
  status: string;
  lastStepUpAt: Date | null;
}

/**
 * The identity half of M7's cross-service account lock (docs/03 §5.1 control
 * 4). Settlement enforces WHO may trigger a transition (its operator
 * allowlist, its state machine); identity enforces WHAT transitions an
 * account can undergo — the table above is deliberately closed. 'locked',
 * 'suspended' and 'closed' are ops states this API can never touch, and
 * 'settlement' is never reversible here: un-verifying a death is an operator
 * ceremony that does not exist yet, not a service call.
 */
@Injectable()
export class SettlementLockService {
  constructor(
    private readonly users: UsersRepo,
    private readonly sessions: SessionsRepo,
    private readonly authEvents: AuthEventsRepo,
    private readonly events: EventsService,
  ) {}

  async setState(
    userId: string,
    state: SettlementLockState,
    caseId: string,
    now: Date,
    /** Owner-liveness watermark: refuse if a step-up was granted after it. */
    livenessNotAfter?: Date,
  ): Promise<{ status: string }> {
    const user = await this.users.findById(userId);
    if (!user) {
      throw new NotFoundException({ error: 'not_found' });
    }
    if (user.status === state) {
      // Idempotent: settlement retries (or a replayed effect) are no-ops.
      return { status: user.status };
    }
    const updated = await this.users.updateStatusFrom(
      userId,
      ALLOWED_TRANSITIONS[state],
      state,
      livenessNotAfter,
    );
    if (!updated) {
      // Two ways to land here: the row sat outside the allowed 'from' set, or
      // the liveness interlock fired. Distinguish them — a caller told
      // "invalid_transition" would retry, while "owner_alive" means the case
      // must be voided instead.
      if (livenessNotAfter) {
        const lastStepUpAt = await this.authEvents.lastOccurredAt(userId, 'stepup.granted');
        if (lastStepUpAt && lastStepUpAt.getTime() > livenessNotAfter.getTime()) {
          throw new ConflictException({ error: 'owner_alive' });
        }
      }
      throw new ConflictException({ error: 'invalid_transition' });
    }
    await this.authEvents.insert({ userId, kind: 'settlement.status_changed', decision: state });
    await this.events.userStatusChanged(userId, user.status, state, caseId);

    if (state === 'settlement') {
      // Verified: no credential minted by the decedent survives. The session
      // allowlist in SessionsRepo enforces the same rule in SQL; revocation
      // here makes it visible and permanent.
      const revoked = await this.sessions.revokeAllForUser(userId, 'settlement_verified', now);
      await this.events.sessionsRevokedAll(userId, revoked.length, caseId);
    }
    return { status: state };
  }

  /**
   * Owner-liveness answer for settlement's void re-check: the last time this
   * user proved themselves with step-up MFA. Read from the append-only
   * auth_events ledger so revoked/expired sessions still count — the owner
   * signing in yesterday and closing the tab is still a living owner.
   */
  async liveness(userId: string): Promise<LivenessResult> {
    const user = await this.users.findById(userId);
    if (!user) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const lastStepUpAt = await this.authEvents.lastOccurredAt(userId, 'stepup.granted');
    return { status: user.status, lastStepUpAt };
  }
}
