import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { CLOCK, CONFIG, NOTIFIER, type Clock } from './di-tokens';
import type { VaultConfig } from './config';
import { Db, type Queryable } from './db';
import { EmergencyRepo, type PolicyRow } from './emergency.repo';
import { EventsService } from './events.service';
import { KeysetsRepo } from './keysets.repo';
import type { EmergencyNotification, NotificationPort } from './notifications';
import { VaultAuthz, vaultResource } from './authz.service';
import { SETTLEMENT_AUTHORITY, type SettlementVaultGate } from '@estate/settlement-client';

/**
 * Internal sentinel: the settlement gate refused. Thrown from inside the
 * transaction so the write unwinds, then converted to an audited 403 outside.
 */
class SettlementGateError extends Error {
  constructor(readonly caseId: string | null) {
    super('settlement gate refused emergency access');
    this.name = 'SettlementGateError';
  }
}

export interface GranteeInput {
  readonly granteeContactId: string;
  readonly granteeUserId: string;
  readonly keyShare: string;
  readonly granteePublicKeySha256: string;
  readonly waitingPeriodHours: number;
}

export interface PolicyDto {
  readonly id: string;
  readonly granteeContactId: string;
  readonly granteeUserId: string;
  readonly waitingPeriodHours: number;
  readonly status: PolicyRow['status'];
  readonly requestedAt: string | null;
  readonly releasesAt: string | null;
  readonly requestCount: number;
}

export interface EscrowDto {
  readonly configured: boolean;
  readonly threshold: number | null;
  readonly policies: readonly PolicyDto[];
}

/** What a grantee sees about an owner's vault - never the vault itself. */
export interface GranteePolicyDto {
  readonly id: string;
  readonly ownerUserId: string;
  readonly status: PolicyRow['status'];
  readonly releasesAt: string | null;
}

/** The material a grantee collects after the waiting period elapses. */
export interface ReleaseDto {
  readonly ownerUserId: string;
  readonly platformPart: string;
  readonly wrappedMasterKeyRecovery: string;
  readonly keyShare: string;
  readonly threshold: number;
}

function toPolicyDto(row: PolicyRow): PolicyDto {
  return {
    id: row.id,
    granteeContactId: row.grantee_contact_id,
    granteeUserId: row.grantee_user_id,
    waitingPeriodHours: row.waiting_period_hours,
    status: row.status,
    requestedAt: row.requested_at?.toISOString() ?? null,
    releasesAt: row.releases_at?.toISOString() ?? null,
    requestCount: row.request_count,
  };
}

/**
 * Emergency access: the flow that lets a designated contact open a vault when
 * the owner cannot, without letting them do it quietly.
 *
 * docs/03 §5.2 names the attack precisely - a contact invoking access while the
 * owner is alive but unaware - so read the guards here as answers to it:
 *
 *  - The waiting period is enforced by the PLATFORM half of the recovery key.
 *    Every grantee colluding still cannot reconstruct it, so "wait" is not an
 *    honour system.
 *  - Denial is STICKY. A denied policy refuses further requests until the owner
 *    re-arms it. Without that, a patient grantee just re-requests every week
 *    until the owner is hospitalised or offline - which is the attack.
 *  - Release is ONE-SHOT. Once the platform half is handed over, that escrow is
 *    spent; the owner has to build a new one. `revoked` cannot un-ring a bell.
 *  - Every attempt is audited AND notified, including the ones that were
 *    refused, because the owner's after-the-fact review is a control.
 */
@Injectable()
export class EmergencyAccessService {
  constructor(
    private readonly db: Db,
    private readonly emergency: EmergencyRepo,
    private readonly keysets: KeysetsRepo,
    private readonly authz: VaultAuthz,
    private readonly events: EventsService,
    @Inject(NOTIFIER) private readonly notifier: NotificationPort,
    @Inject(SETTLEMENT_AUTHORITY) private readonly settlement: SettlementVaultGate,
    @Inject(CONFIG) private readonly config: VaultConfig,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /**
   * Refuse to arm an escrow that the owner could never be warned about.
   *
   * docs/03 §5.2's control is a waiting period the owner can interrupt. With no
   * real notification channel there is nothing to interrupt it with, so in
   * production this fails closed rather than shipping a control that only looks
   * like one. Dev and test run against the stub deliberately.
   */
  private async assertNotificationsUsable(): Promise<void> {
    if (this.config.nodeEnv === 'production' && !this.notifier.deliversToRealChannels) {
      // The refusal is a control firing, and as of M9 it is VISIBLE: a
      // production vault silently 503ing emergency access would otherwise be
      // indistinguishable from an outage in the very stream operators watch.
      await this.auditRefusal('adapter_unwired', null);
      throw new ServiceUnavailableException({ error: 'notifications_unavailable' });
    }
  }

  /**
   * THE ARMING GATE (M14): refuse to arm an escrow for an owner whose address
   * nobody has proved.
   *
   * `deliversToRealChannels` above asks whether SES is wired. It is a hardcoded
   * literal on an adapter class, so it cannot be wrong about a recipient — it
   * never looks at one. That is the gap M14 closes: an escrow could arm, the
   * §5.2 clock could start, and the notification meant to let the owner
   * INTERRUPT it could be going to an address they had never confirmed. Worst
   * for the dormant owner, whose stored address is stalest precisely because
   * the only self-heal was a login.
   *
   * ARMING-CLASS, so it REFUSES rather than recording. The actor and the
   * recipient are the same person here — the owner is configuring their own
   * escrow — so refusing costs them an action they can unblock themselves by
   * verifying, and never denies a third party. That asymmetry is the whole
   * classification: `request`, `release` and settlement's intake proceed and
   * record instead, because there the actor is a grantee, a redeemer or a
   * reporter, and an owner's own typo must not be able to lock them out.
   *
   * Production-scoped, extending the existing condition rather than adding a
   * second shape: dev and test run against the stub by design, and gating them
   * would mean threading the whole ceremony through every fixture.
   */
  private async assertOwnerReachable(ownerUserId: string): Promise<void> {
    if (this.config.nodeEnv !== 'production') {
      return;
    }
    // Fail closed: the port collapses an unanswerable query to false, and an
    // outage therefore delays a legitimate owner by minutes rather than handing
    // an attacker the waiting period.
    if (!(await this.notifier.recipientVerified(ownerUserId))) {
      await this.auditRefusal('recipient_unverified', ownerUserId);
      throw new ServiceUnavailableException({ error: 'recipient_unverified' });
    }
  }

  /**
   * A control firing must never read as an outage (the M9 rule). The REASON is
   * an enum token, because "SES is not wired" and "this owner never confirmed
   * their address" call for completely different operator responses.
   */
  private async auditRefusal(
    reason: 'adapter_unwired' | 'recipient_unverified',
    ownerUserId: string | null,
  ): Promise<void> {
    await this.events.audit.emit({
      action: 'vault.emergency.notifications_refused',
      actorId: null,
      actorType: 'system',
      onBehalfOf: ownerUserId,
      resourceType: 'vault',
      resourceId: null,
      sessionId: null,
      detail: { reason },
    });
  }

  private async notify(
    notification: EmergencyNotification,
    policyId: string | null,
    ownerUserId: string,
  ): Promise<void> {
    let deliveredAt: Date | null = null;
    let recipientVerified = false;
    try {
      const outcome = await this.notifier.notify(notification);
      // A failed notification must not roll back the state change: the request
      // still happened and the owner still needs the record. The null
      // delivered_at is the signal that a channel let us down.
      deliveredAt = outcome.delivered ? this.clock() : null;
      recipientVerified = outcome.recipientVerified;
    } catch {
      // The port narrows failures to outcomes now, so reaching here means an
      // adapter broke its own contract. Recorded as a non-delivery either way.
    }
    await this.emergency.recordNotification(this.db, {
      policyId,
      userId: ownerUserId,
      kind: notification.kind,
      channel: this.notifier.channel,
      deliveredAt,
    });
    // M14, the PROCEED-AND-RECORD half. `request` and `release` are driven by a
    // GRANTEE, so they must not be blocked by the OWNER's unverified address —
    // that would let an owner's typo permanently deny a legitimate emergency
    // contact, the M6 rule pointed the wrong way. The fact still has to land
    // somewhere the §5.2 record can be read from, and this is it: an alert sent
    // to an unproved address is not evidence the owner could have interrupted
    // anything.
    if (deliveredAt !== null && !recipientVerified) {
      await this.events.audit.emit({
        action: 'vault.emergency.unverified_recipient',
        actorId: null,
        actorType: 'system',
        onBehalfOf: ownerUserId,
        resourceType: 'vault',
        resourceId: policyId,
        sessionId: null,
        detail: { kind: notification.kind },
      });
    }
  }

  /** Publish this user's public key so others can name them as a contact. */
  async publishRecoveryKey(
    actorUserId: string,
    accountSessionId: string,
    input: { publicKey: string; wrappedPrivateKey: string },
  ): Promise<{ published: boolean }> {
    this.authz.assertCan(actorUserId, 'manage', vaultResource(actorUserId));

    await this.db.withTransaction(actorUserId, async (tx) => {
      const keyset = await this.keysets.lockByUser(tx, actorUserId);
      if (!keyset) throw new NotFoundException({ error: 'keyset_not_found' });
      await this.keysets.setRecoveryKeyPair(tx, {
        userId: actorUserId,
        publicKey: Buffer.from(input.publicKey, 'base64'),
        wrappedPrivateKey: Buffer.from(input.wrappedPrivateKey, 'base64'),
      });
    });

    await this.events.recoveryKeyPublished(actorUserId, accountSessionId);
    return { published: true };
  }

  /**
   * The caller's OWN recovery keypair.
   *
   * Returns ciphertext the caller alone can open: `wrapped_private_key` is
   * sealed under their master key, so this is the same class of response as the
   * `wrappedMasterKey` an unlock already returns. Gated on an OPEN VAULT rather
   * than a bare session, which is deliberate — a grantee completing a release
   * must be able to open their own vault, so a stolen bearer token alone
   * achieves nothing here.
   *
   * Without this route the emergency-access design could not complete: M6 wrote
   * the wrapped private key and served it to nobody, so a share sealed to a
   * grantee could never be opened by that grantee. It had no client until M15
   * PR3, which is why nothing noticed.
   */
  async ownRecoveryKey(
    actorUserId: string,
  ): Promise<{ publicKey: string; wrappedPrivateKey: string }> {
    this.authz.assertCan(actorUserId, 'read', vaultResource(actorUserId));
    const pair = await this.keysets.findRecoveryKeyPair(this.db, actorUserId);
    if (!pair) throw new NotFoundException({ error: 'recovery_key_not_found' });
    return {
      publicKey: pair.publicKey.toString('base64'),
      wrappedPrivateKey: pair.wrappedPrivateKey.toString('base64'),
    };
  }

  /**
   * Look up a prospective grantee's public key. The owner's client is expected
   * to confirm its fingerprint with the grantee over a channel this platform
   * does not control before sealing anything to it - without that step a
   * malicious server could substitute its own key here and read the escrow.
   */
  async granteePublicKey(
    actorUserId: string,
    granteeUserId: string,
  ): Promise<{ granteeUserId: string; publicKey: string }> {
    this.authz.assertCan(actorUserId, 'read', vaultResource(actorUserId));
    const publicKey = await this.keysets.findPublicKey(this.db, granteeUserId);
    if (!publicKey) throw new NotFoundException({ error: 'grantee_key_not_found' });
    return { granteeUserId, publicKey: publicKey.toString('base64') };
  }

  async describe(actorUserId: string): Promise<EscrowDto> {
    this.authz.assertCan(actorUserId, 'read', vaultResource(actorUserId));
    const [config, policies] = await Promise.all([
      this.emergency.findConfig(this.db, actorUserId),
      this.emergency.listByOwner(this.db, actorUserId),
    ]);
    return {
      configured: config !== null,
      threshold: config?.threshold ?? null,
      policies: policies.map(toPolicyDto),
    };
  }

  /**
   * Arm (or re-arm from scratch) the escrow. Wholesale replacement: the client
   * has already split a fresh recovery key across the grantee set, so keeping
   * old policies would leave shares of a key that no longer opens anything.
   */
  async configure(
    actorUserId: string,
    accountSessionId: string,
    input: {
      threshold: number;
      platformPart: string;
      wrappedMasterKeyRecovery: string;
      grantees: readonly GranteeInput[];
    },
  ): Promise<EscrowDto> {
    this.authz.assertCan(actorUserId, 'manage', vaultResource(actorUserId));
    await this.assertNotificationsUsable();
    // ARMS a capability (M14): the escrow this creates is what a grantee later
    // starts the §5.2 clock against, so the owner must be provably reachable
    // before it exists.
    await this.assertOwnerReachable(actorUserId);

    if (input.grantees.length === 0) throw new ConflictException({ error: 'no_grantees' });
    if (input.threshold > input.grantees.length) {
      throw new ConflictException({ error: 'threshold_exceeds_grantees' });
    }
    const granteeIds = new Set(input.grantees.map((g) => g.granteeUserId));
    if (granteeIds.size !== input.grantees.length) {
      throw new ConflictException({ error: 'duplicate_grantee' });
    }
    if (granteeIds.has(actorUserId)) {
      // Naming yourself would make the escrow a second key to your own vault
      // with a waiting period attached - strictly worse than the vault itself.
      throw new ConflictException({ error: 'self_grantee' });
    }

    const now = this.clock();
    const result = await this.db.withTransaction(actorUserId, async (tx) => {
      const keyset = await this.keysets.lockByUser(tx, actorUserId);
      if (!keyset) throw new NotFoundException({ error: 'keyset_not_found' });

      // Any release in flight dies with the old escrow.
      const retired = await this.emergency.softDeleteAllForOwner(tx, actorUserId, now);
      await this.emergency.upsertConfig(tx, {
        userId: actorUserId,
        threshold: input.threshold,
        platformPart: Buffer.from(input.platformPart, 'base64'),
        wrappedMasterKeyRecovery: Buffer.from(input.wrappedMasterKeyRecovery, 'base64'),
      });

      const rows: PolicyRow[] = [];
      for (const grantee of input.grantees) {
        rows.push(
          await this.emergency.insertPolicy(tx, {
            userId: actorUserId,
            granteeContactId: grantee.granteeContactId,
            granteeUserId: grantee.granteeUserId,
            waitingPeriodHours: grantee.waitingPeriodHours,
            keyShare: Buffer.from(grantee.keyShare, 'base64'),
            granteePublicKeySha256: Buffer.from(grantee.granteePublicKeySha256, 'base64'),
          }),
        );
      }
      return { rows, retired };
    });

    await this.events.emergencyConfigured(actorUserId, accountSessionId, {
      grantees: result.rows.length,
      threshold: input.threshold,
    });
    if (result.retired > 0) {
      // The M6 review's recorded gap: a reconfiguration silently retired the
      // previous grantees. The owner is told (anchored to the new escrow's
      // first policy) — if THEY did it, it is a receipt; if not, it is the
      // alarm before the new arrangement's waiting period can matter.
      const anchor = result.rows[0]?.id ?? null;
      await this.notify(
        { kind: 'grantees_changed', ownerUserId: actorUserId, policyId: anchor },
        anchor,
        actorUserId,
      );
    }
    return {
      configured: true,
      threshold: input.threshold,
      policies: result.rows.map(toPolicyDto),
    };
  }

  /** What a grantee has been designated for. Never reveals vault contents. */
  async listForGrantee(granteeUserId: string): Promise<readonly GranteePolicyDto[]> {
    const rows = await this.emergency.listByGrantee(this.db, granteeUserId);
    return rows.map((row) => ({
      id: row.id,
      ownerUserId: row.user_id,
      status: row.status,
      releasesAt: row.releases_at?.toISOString() ?? null,
    }));
  }

  /**
   * A grantee asks to open the owner's vault. This never grants anything - it
   * starts the clock and tells the owner.
   */
  async request(
    granteeUserId: string,
    accountSessionId: string,
    policyId: string,
  ): Promise<PolicyDto> {
    await this.assertNotificationsUsable();
    const now = this.clock();

    const outcome = await this.withSettlementGate(granteeUserId, accountSessionId, policyId, () =>
      this.db.withTransaction(granteeUserId, async (tx) => {
        const policy = await this.requireGranteePolicy(tx, policyId, granteeUserId);
        // The settlement gate (docs/03 §6a / §5.1 control 5). Checked BEFORE the
        // clock starts: if the owner's estate is in settlement without an
        // approved vault stage, the waiting period must never begin, so a
        // grantee cannot pre-position a request to mature the instant a stage
        // lands.
        await this.assertSettlementPermits(policy.user_id);

        const blocked = this.blockReason(policy);
        if (blocked) {
          // Counted and reported, not silently dropped: a grantee hammering a
          // denied policy is exactly what the owner needs to see.
          await this.emergency.countBlockedRequest(tx, policy.id);
          return { blocked, policy };
        }

        const releasesAt = new Date(now.getTime() + policy.waiting_period_hours * 60 * 60 * 1000);
        const updated = await this.emergency.markRequested(tx, {
          id: policy.id,
          at: now,
          releasesAt,
        });
        return { blocked: null, policy: updated };
      }),
    );

    if (outcome.blocked) {
      await this.events.emergencyRequestBlocked(
        granteeUserId,
        accountSessionId,
        outcome.policy.id,
        outcome.blocked,
      );
      await this.notify(
        { kind: 'blocked', ownerUserId: outcome.policy.user_id, policyId: outcome.policy.id },
        outcome.policy.id,
        outcome.policy.user_id,
      );
      throw new ConflictException({ error: outcome.blocked });
    }

    await this.events.emergencyRequested(granteeUserId, accountSessionId, outcome.policy.id, {
      waitingPeriodHours: outcome.policy.waiting_period_hours,
    });
    await this.notify(
      {
        kind: 'requested',
        ownerUserId: outcome.policy.user_id,
        policyId: outcome.policy.id,
        ...(outcome.policy.releases_at ? { releasesAt: outcome.policy.releases_at } : {}),
      },
      outcome.policy.id,
      outcome.policy.user_id,
    );
    return toPolicyDto(outcome.policy);
  }

  /**
   * Why this request cannot proceed, or null if it can.
   *
   * There is no time-based cooldown here on purpose. A cooldown would let a
   * denied grantee back in automatically once it expired, which is precisely
   * the grinding attack docs/03 §5.2 describes. The denial is sticky instead:
   * it holds until the OWNER re-arms the policy, so waiting the owner out
   * stops working.
   */
  private blockReason(policy: PolicyRow): string | null {
    if (policy.status === 'revoked') return 'policy_revoked';
    if (policy.status === 'released') return 'already_released';
    if (policy.status === 'waiting') return 'already_waiting';
    if (policy.status === 'denied_by_owner') return 'denied_by_owner';
    return null;
  }

  /**
   * The owner says no. CallerGuard only, deliberately: this has to be one tap
   * from a notification on a phone, and a step-up prompt between the owner and
   * "stop this" is a control that argues with itself.
   */
  async deny(ownerUserId: string, accountSessionId: string, policyId: string): Promise<PolicyDto> {
    const now = this.clock();
    const updated = await this.db.withTransaction(ownerUserId, async (tx) => {
      const policy = await this.requireOwnerPolicy(tx, policyId, ownerUserId);
      if (policy.status === 'released') throw new ConflictException({ error: 'already_released' });
      if (policy.status === 'revoked') throw new ConflictException({ error: 'policy_revoked' });
      return this.emergency.markDenied(tx, policy.id, now);
    });

    await this.events.emergencyDenied(ownerUserId, accountSessionId, updated.id);
    return toPolicyDto(updated);
  }

  /** Clear a denial so the contact can request again. Step-up gated. */
  async rearm(ownerUserId: string, accountSessionId: string, policyId: string): Promise<PolicyDto> {
    await this.assertNotificationsUsable();
    // ARMS, and this one was not in M14's original table. Re-arming restores a
    // grantee's ability to start the §5.2 clock — a denial is sticky with no
    // cooldown precisely so it stays the owner's decision — and the actor here
    // IS the recipient, so refusing costs the owner an action they can unblock
    // themselves rather than denying a third party.
    await this.assertOwnerReachable(ownerUserId);
    const updated = await this.db.withTransaction(ownerUserId, async (tx) => {
      const policy = await this.requireOwnerPolicy(tx, policyId, ownerUserId);
      if (policy.status === 'released') throw new ConflictException({ error: 'already_released' });
      if (policy.status === 'revoked') throw new ConflictException({ error: 'policy_revoked' });
      return this.emergency.markRearmed(tx, policy.id);
    });

    await this.events.emergencyRearmed(ownerUserId, accountSessionId, updated.id);
    return toPolicyDto(updated);
  }

  /** Remove a grantee entirely. Step-up gated (docs/01 §5). */
  async revoke(ownerUserId: string, accountSessionId: string, policyId: string): Promise<void> {
    const now = this.clock();
    const updated = await this.db.withTransaction(ownerUserId, async (tx) => {
      const policy = await this.requireOwnerPolicy(tx, policyId, ownerUserId);
      return this.emergency.markRevoked(tx, policy.id, now);
    });

    await this.events.emergencyRevoked(ownerUserId, accountSessionId, updated.id);
    await this.notify(
      { kind: 'revoked', ownerUserId, policyId: updated.id },
      updated.id,
      ownerUserId,
    );
  }

  /**
   * The grantee collects the escrow material once the waiting period has run
   * without a denial. This is the only moment the platform half leaves the
   * server, and it happens exactly once per escrow.
   */
  async release(
    granteeUserId: string,
    accountSessionId: string,
    policyId: string,
  ): Promise<ReleaseDto> {
    const now = this.clock();

    const released = await this.withSettlementGate(granteeUserId, accountSessionId, policyId, () =>
      this.db.withTransaction(granteeUserId, async (tx) => {
        const policy = await this.requireGranteePolicy(tx, policyId, granteeUserId);

        if (policy.status === 'denied_by_owner')
          throw new ForbiddenException({ error: 'denied_by_owner' });
        if (policy.status === 'revoked') throw new ForbiddenException({ error: 'policy_revoked' });
        if (policy.status === 'released')
          throw new ConflictException({ error: 'already_released' });
        if (policy.status !== 'waiting' || !policy.releases_at) {
          throw new ConflictException({ error: 'not_requested' });
        }
        if (policy.releases_at.getTime() > now.getTime()) {
          throw new ForbiddenException({ error: 'waiting_period_active' });
        }

        // The settlement gate again, INSIDE the transaction and after the row
        // lock (docs/03 §6a). Re-checked here because the waiting period is days
        // long: an estate can enter settlement between the request and the
        // collection, and Zone A is the stage that must come last.
        await this.assertSettlementPermits(policy.user_id);

        const config = await this.emergency.lockConfig(tx, policy.user_id);
        if (!config) throw new NotFoundException({ error: 'escrow_not_found' });

        const updated = await this.emergency.markReleased(tx, policy.id, now);
        return { policy: updated, config };
      }),
    );

    await this.events.emergencyReleased(
      granteeUserId,
      accountSessionId,
      released.policy.id,
      released.policy.user_id,
    );
    await this.notify(
      { kind: 'released', ownerUserId: released.policy.user_id, policyId: released.policy.id },
      released.policy.id,
      released.policy.user_id,
    );

    return {
      ownerUserId: released.policy.user_id,
      platformPart: released.config.platform_part.toString('base64'),
      wrappedMasterKeyRecovery: released.config.wrapped_master_key_recovery.toString('base64'),
      keyShare: released.policy.key_share_ct.toString('base64'),
      threshold: released.config.threshold,
    };
  }

  /**
   * The docs/03 §6a integration point: emergency access is the LAST staged
   * grant of a settlement (§5.1 control 5), so it must not proceed while the
   * owner's estate is in settlement without an approved `vault` stage.
   *
   * Fails CLOSED. An unreachable settlement service blocks release — the
   * client returns `permitted: false` on every error path. That direction is
   * deliberate: the failure mode of blocking is a delayed legitimate recovery,
   * which the owner or an operator can clear; the failure mode of allowing is
   * handing a fraudulent "heir" the platform half of the recovery key during
   * exactly the window §5.1 exists to protect.
   */
  private async assertSettlementPermits(ownerUserId: string): Promise<void> {
    const answer = await this.settlement.checkVaultRelease({ ownerUserId });
    if (!answer.permitted) {
      throw new SettlementGateError(answer.caseId);
    }
  }

  /**
   * Run `fn`, converting a gate refusal into an audited 403. The audit event
   * is emitted AFTER the transaction unwinds (the established pattern), so a
   * blocked attempt is recorded even though nothing was written — a grantee
   * probing a settled estate is precisely what the owner's estate needs
   * visible.
   */
  private async withSettlementGate<T>(
    granteeUserId: string,
    accountSessionId: string,
    policyId: string,
    fn: () => Promise<T>,
  ): Promise<T> {
    try {
      return await fn();
    } catch (err) {
      if (!(err instanceof SettlementGateError)) {
        throw err;
      }
      await this.events.emergencyReleaseBlocked(
        granteeUserId,
        accountSessionId,
        policyId,
        err.caseId,
      );
      throw new ForbiddenException({ error: 'settlement_stage_not_reached' });
    }
  }

  private async requireOwnerPolicy(
    tx: Queryable,
    policyId: string,
    ownerUserId: string,
  ): Promise<PolicyRow> {
    const policy = await this.emergency.lockLiveByIdForOwner(tx, policyId, ownerUserId);
    if (!policy) throw new NotFoundException({ error: 'not_found' });
    // Cedar still decides the ACTION on the owner's own vault; what it no
    // longer decides is ownership, because a policy belonging to somebody else
    // never arrives here to be refused distinguishably.
    this.authz.assertCan(ownerUserId, 'manage', vaultResource(policy.user_id));
    return policy;
  }

  private async requireGranteePolicy(
    tx: Queryable,
    policyId: string,
    granteeUserId: string,
  ): Promise<PolicyRow> {
    // Not a Cedar decision: the grantee is not the resource owner, and the
    // bundled owner policy would (correctly) deny. Designation IS the grant,
    // and it is recorded on this row — so the designation is the WHERE clause.
    // This arm already answered a uniform 404 by comparing after the read; M27
    // PR1a fused it so both arms of this file spell the rule one way.
    const policy = await this.emergency.lockLiveByIdForGrantee(tx, policyId, granteeUserId);
    if (!policy) throw new NotFoundException({ error: 'not_found' });
    return policy;
  }
}
