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
import { VaultAuthz, vaultItemResource, vaultResource } from './authz.service';
import { ItemsRepo, type ItemRow } from './items.repo';
import { decodeCursor, encodeCursor, toDto, type VaultItemPage } from './vault.service';
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
  /**
   * WHEN A COLLECTION LAST HAPPENED, AND IT IS ON THE DTO BECAUSE `deny` NOW
   * OVERWRITES THE STATUS THAT USED TO CARRY THAT FACT (M27 PR3a review).
   *
   * `deny` refused on a released policy until this milestone, so `status`
   * itself was the durable record: a policy that had handed over the master
   * key stayed `released` and said so. Admitting deny — which the same PR had
   * to do, or the only ungated stop would have been unavailable exactly where
   * the permissive action became repeatable — writes `denied_by_owner` over
   * it, and `markDenied` clears `releases_at` too. Without this field the
   * owner's escrow view returns a BYTE-IDENTICAL row for "I stopped them
   * before anything left the server" and "I stopped them after they rebuilt my
   * master key", which are the two states in this whole feature whose remedies
   * differ most: the second requires a vault reset and the first requires
   * nothing.
   *
   * A bare timestamp carries no key material and no PII, which is why the fix
   * is exposing the column the row already has rather than reinstating the
   * refusal — reinstating it would restore the defect PR3a exists to remove.
   */
  readonly releasedAt: string | null;
  readonly requestCount: number;
}

export interface EscrowDto {
  readonly configured: boolean;
  readonly threshold: number | null;
  /**
   * M27 PR3b. What the owner chose to call this vault, echoed back so the
   * screen that SET it can show it — an owner who cannot see the current label
   * cannot tell an empty one from one that failed to save.
   */
  readonly label: string | null;
  readonly policies: readonly PolicyDto[];
}

/** What a grantee sees about an owner's vault - never the vault itself. */
export interface GranteePolicyDto {
  readonly id: string;
  readonly ownerUserId: string;
  readonly status: PolicyRow['status'];
  readonly releasesAt: string | null;
  /** See `PolicyDto.releasedAt`; the grantee's own row loses the fact the same way. */
  readonly releasedAt: string | null;
  /**
   * M27 PR3b, closing docs/03 §6yy's `[OWNER: M27]`. What the OWNER chose to
   * call their vault, or null — in which case the surface falls back to
   * `ownerUserId`, which is what it printed before PR3b and is not a secret to
   * a reader who was sealed a share by that account.
   *
   * NOT the owner's name, and the distinction is the disclosure decision this
   * residual asked for: the platform has no name for an account anywhere (a
   * person's name exists only inside OTHER users' per-user-encrypted contact
   * rows), so the only string that can be served here without inventing a
   * Zone B identity field is one the owner wrote for this purpose.
   */
  readonly ownerLabel: string | null;
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
    releasedAt: row.released_at?.toISOString() ?? null,
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
    private readonly items: ItemsRepo,
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
      label: config?.label ?? null,
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
      label?: string | undefined;
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
        // `?? null` rather than a spread: configure REPLACES an escrow, so an
        // absent label must clear the previous one rather than inherit it.
        label: input.label ?? null,
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
      label: input.label ?? null,
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
      releasedAt: row.released_at?.toISOString() ?? null,
      ownerLabel: row.owner_label,
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

    const outcome = await this.withSettlementGate(
      granteeUserId,
      accountSessionId,
      policyId,
      'request',
      () =>
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
    if (policy.status === 'released') return 'already_released';
    if (policy.status === 'waiting') return 'already_waiting';
    if (policy.status === 'denied_by_owner') return 'denied_by_owner';
    return null;
  }

  /**
   * The owner says no. CallerGuard only, deliberately: this has to be one tap
   * from a notification on a phone, and a step-up prompt between the owner and
   * "stop this" is a control that argues with itself.
   *
   * ADMITTED ON A RELEASED POLICY SINCE M27 PR3a, and that is not a convenience
   * — it is what makes re-collectable release legal under docs/03's rule that
   * the protective action must never be harder than the permissive one. Release
   * is CallerGuard only; `revoke`, the other stop, is `@UseGuards(StepUpGuard)`.
   * Leaving this refused while release repeated would have put the permissive
   * action one call away and the only ungated stop behind fresh MFA — the rule
   * inverted, in the change that cited it.
   *
   * IT CANNOT UN-RELEASE WHAT THE GRANTEE ALREADY HOLDS. The escrow material
   * left the server on the first collection and the master key was rebuilt on
   * their device; a denial ends the arrangement's ability to hand over MORE.
   * `markDenied` does that with no new transition: `denied_by_owner` is refused
   * by the release guard above, and the `releases_at = NULL` it also writes is
   * belt-and-braces behind that. Sticky, no cooldown, until the owner re-arms —
   * exactly what deny has always meant.
   *
   * `rearm` still answers `already_released` on a released policy, and that is
   * a SPEED BUMP RATHER THAN A BOUNDARY — stated here because the first draft
   * of this paragraph presented it as a decided limit. Since deny now admits,
   * an owner can deny (one tap, CallerGuard) and then rearm (step-up), landing
   * the policy at `configured` with `releases_at` cleared. That is not an
   * authority bypass: both are owner actions, rearm still demands fresh MFA,
   * and the result is a policy that must serve a fresh waiting period before
   * anything can be collected — which is the arming ceremony working, not
   * being evaded. What it is not is a rule, and a comment claiming otherwise
   * would be a control that exists only on paper.
   */
  async deny(ownerUserId: string, accountSessionId: string, policyId: string): Promise<PolicyDto> {
    const now = this.clock();
    const updated = await this.db.withTransaction(ownerUserId, async (tx) => {
      const policy = await this.requireOwnerPolicy(tx, policyId, ownerUserId);
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
   * server.
   *
   * IT IS REPEATABLE SINCE M27 PR3a. This sentence used to end by promising the
   * collection happened a single time per escrow, which was the ceremony's
   * central defect stated as if it were a guarantee: a dropped connection or a
   * closed tab consumed the arrangement and delivered nothing, recoverable only
   * by an owner re-arming — the one thing an incapacitated owner cannot do. See
   * the guard below for why repeating it destroys nothing, and `deny` for the
   * stop that moved with it. (Described rather than quoted, so a repo-wide
   * sweep for the old claim does not report this explanation as an instance of
   * it — the same reason `apps/vault-web/test/fences.spec.ts` gives.)
   */
  async release(
    granteeUserId: string,
    accountSessionId: string,
    policyId: string,
  ): Promise<ReleaseDto> {
    const now = this.clock();

    const released = await this.withSettlementGate(
      granteeUserId,
      accountSessionId,
      policyId,
      'release',
      () =>
        this.db.withTransaction(granteeUserId, async (tx) => {
          const policy = await this.requireGranteePolicy(tx, policyId, granteeUserId);

          if (policy.status === 'denied_by_owner')
            throw new ForbiddenException({ error: 'denied_by_owner' });
          /*
           * NO `revoked` ARM ANYWHERE IN THIS SERVICE, AND THE ABSENCE IS
           * FENCED (M27 PR3b review, corrected in the same review).
           *
           * `status='revoked'` is unobservable to every route here.
           * `markRevoked` is the only writer of it and sets `deleted_at` in the
           * SAME statement, while `lockLiveByIdForGrantee` and
           * `lockLiveByIdForOwner` — the two reads every policy route goes
           * through — both filter `deleted_at IS NULL`. A revoked policy
           * therefore answers the uniform 404, which is the right answer
           * anyway, being indistinguishable from "not yours".
           *
           * FIVE arms tested for it and all five were dead: `release` and
           * `readAsGrantee` here, `blockReason` on the grantee request path,
           * and `deny` and `rearm` on the owner's. The first pass removed two —
           * the two a LINE coverage floor could see, because their `throw` was
           * the whole statement. The other three sat on an `if` that executes
           * on every call and only never takes its branch, which a line floor
           * cannot see and a 78% branch floor did not force. Removing two of
           * five is this repo's "a rule applied to one member of a category is
           * a rule half-applied", committed inside the change that cites it.
           *
           * The invariant is asserted rather than described:
           * `revoked-is-unobservable.spec.ts` reads `emergency.repo.ts` and
           * fails if `markRevoked` ever stops soft-deleting in the same
           * statement, or if any `lockLive*` lookup stops filtering
           * `deleted_at IS NULL`. Either change makes these arms live again and
           * the fence is what says so.
           */
          /*
           * RE-COLLECTABLE (M27 PR3a), and it is ONE guard because it was two.
           *
           * `released` used to be refused here with `already_released`, which made
           * the §5.2 ceremony spend itself and deliver nothing: a grantee who
           * closed the tab consumed the arrangement in the one scenario the
           * feature exists for. Nothing was ever destroyed to justify it — `markReleased`
           * sets `status` and `released_at` and touches neither `key_share_ct` nor
           * anything in `emergency_access_configs` — so "one-shot" was a status
           * check wearing a cryptographic one-way door's clothes.
           *
           * REMOVING ONLY THAT THROW WOULD HAVE CHANGED NOTHING. The caller fell
           * straight into the next line, `status !== 'waiting'`, and got
           * `not_requested` — the same dead end reported under a token that means
           * something else, which is the two-failures-one-token defect docs/03
           * forbids. The M27 PR0 review reproduced that against a real database
           * rather than reading the guard order, which is why both are replaced by
           * a single predicate naming what collectable actually means.
           *
           * `releases_at` survives a RELEASE — `markReleased` does not touch it —
           * so the elapsed check below still governs every collection rather than
           * just the first. THREE writers clear it, not one: `markDenied`,
           * `markRearmed` and `markRevoked`. An earlier draft of this comment
           * said "only `markDenied`", which is the shape CLAUDE.md warns about —
           * a comment justifying itself with a fact about the tree that nobody
           * checks — and it was wrong. The conclusion survives because all three
           * also move `status` out of the collectable set, which is the property
           * actually relied on here rather than the count of writers.
           */
          const collectable = policy.status === 'waiting' || policy.status === 'released';
          if (!collectable || !policy.releases_at) {
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
   * THE GRANTEE'S READ (M27 PR3b) — the surface the whole §5.2 ceremony exists
   * to reach, and the first place in this service where one user is handed
   * another user's Zone A rows.
   *
   * WHAT AUTHORIZES IT, in the order the request meets it:
   *
   *   1. `VaultSessionGuard` on the controller — the grantee's OWN vault is
   *      unlocked. It is not widened to accept the owner's session, and
   *      `owner.cedar` is untouched (docs/03 §6uu settled this in PR0).
   *   2. `requireGranteePolicy`, which locks by (id, grantee) TOGETHER, so a
   *      policy that is not theirs and a policy that does not exist are one
   *      empty result and one 404.
   *   3. `status === 'released'`, re-read inside the transaction. This is what
   *      makes PR3a's one-tap stop actually stop something: `markDenied` and
   *      `markRevoked` move status OUT of `released`, so the next read refuses
   *      without either of them knowing this route exists. `markRearmed` is NOT
   *      a third — `rearm` refuses a released policy with `already_released`
   *      before it — and listing it here was a stale generalisation of the true
   *      statement one guard down, where all three DO clear `releases_at`.
   *   4. The settlement gate, again, inside the transaction — an estate can
   *      enter settlement between the collection and the read, and Zone A is
   *      the stage that must come last.
   *   5. Cedar, per item, over `vault.cedar`'s `read_by_grantee`.
   *
   * WHAT (5) IS AND IS NOT, stated plainly because a mutation caught the first
   * draft of this comment overclaiming it.
   *
   * DELETING THE CEDAR CALL LEAVES THE WHOLE SUITE GREEN except the one test
   * written to pin its shape. That is not a weak test — it is the honest
   * answer: the call CANNOT DENY here today. `listReleasedGranteeIds` selects
   * the owner's policies at `status='released' AND deleted_at IS NULL`, and
   * guard (2) has already returned THIS row under the same two filters, so the
   * principal is in the set by construction. Two derivations of one row.
   *
   * It stays for two reasons that are worth being explicit about rather than
   * dressing up as a gate. First, uniformity: every other read in this service
   * consults the PEP, and making this the single read that does not would be
   * an exception a reader has to discover. Second, it is the attachment point
   * — a later policy that narrows grantee reads by item type or settlement
   * stage is a change to `vault.cedar` and to the resource built here, and to
   * nothing else.
   *
   * The refusal that actually stops a stopped grantee is (3), and
   * `emergency.int.spec.ts` names which layer each of its refusal tests
   * proves. The limit is recorded in docs/03 §6zz, not only here.
   *
   * WHAT IT DELIBERATELY DOES NOT SERVE: deleted items, version history, the
   * restorable list — and any single item. A grantee reads what the owner has
   * now, in one page. The owner's `read_history`, `undelete` and `restore` are
   * separate action ids for exactly this reason (M27 PR1b), and `vault.cedar`
   * names none of them; the missing per-item route is explained on the
   * controller, and it is an absence rather than an omission.
   */
  async listItemsForGrantee(
    granteeUserId: string,
    accountSessionId: string,
    policyId: string,
    query: { limit: number; cursor?: string | undefined },
  ): Promise<VaultItemPage> {
    const read = await this.readAsGrantee(granteeUserId, accountSessionId, policyId, query);

    await this.events.emergencyItemsRead(
      granteeUserId,
      accountSessionId,
      policyId,
      read.ownerUserId,
      { count: read.rows.length, scope: 'live' },
    );

    const last = read.rows.length === query.limit ? read.rows[read.rows.length - 1] : undefined;
    return {
      items: read.rows.map(toDto),
      nextCursor: last ? encodeCursor(last.updated_at, last.id) : null,
    };
  }

  /**
   * The body of the grantee read: authorize, read, and CLAIM the owner's
   * notice — all inside one transaction, with the policy row locked.
   *
   * SEPARATE FROM ITS CALLER even though there is exactly one, because what
   * lives here is every decision that could hand somebody else's rows over,
   * and what lives there is paging and DTO mapping. It took a `read` callback
   * while a second route existed; with that route gone the callback was a
   * generic with one call site, which reads as extensibility and is really
   * just indirection between a reader and the guards they need to check.
   *
   * The claim is in here rather than beside the send for a concurrency reason
   * spelled out on `EmergencyRepo.claimNotification`: `hasNotifiedSince` is the
   * dedupe, so the check and the write have to be in the same transaction or
   * the lock protects nothing and two racing first-reads both notify.
   */
  private async readAsGrantee(
    granteeUserId: string,
    accountSessionId: string,
    policyId: string,
    query: { limit: number; cursor?: string | undefined },
  ): Promise<{ ownerUserId: string; rows: ItemRow[] }> {
    const outcome = await this.withSettlementGate(
      granteeUserId,
      accountSessionId,
      policyId,
      'read',
      () =>
        this.db.withTransaction(granteeUserId, async (tx) => {
          const policy = await this.requireGranteePolicy(tx, policyId, granteeUserId);

          // Named refusals, spelled exactly as `release` spells them: a grantee
          // whose access was stopped must not read the same token as a grantee
          // who never collected, and neither may read as an outage.
          if (policy.status === 'denied_by_owner')
            throw new ForbiddenException({ error: 'denied_by_owner' });
          if (policy.status !== 'released' || !policy.released_at) {
            throw new ConflictException({ error: 'not_collected' });
          }

          await this.assertSettlementPermits(policy.user_id);

          const granteeIds = await this.emergency.listReleasedGranteeIds(tx, policy.user_id);
          const rows = await this.items.listByUser(tx, {
            userId: policy.user_id,
            limit: query.limit,
            ...(query.cursor
              ? { cursor: ((c) => ({ updatedAt: c.at, id: c.id }))(decodeCursor(query.cursor)) }
              : {}),
          });
          for (const row of rows) {
            this.authz.assertCan(
              granteeUserId,
              'read_by_grantee',
              vaultItemResource(row.id, policy.user_id, granteeIds),
            );
          }

          const told = await this.emergency.hasNotifiedSince(tx, {
            policyId: policy.id,
            kind: 'read_by_grantee',
            since: policy.released_at,
          });
          const claimId = told
            ? null
            : await this.emergency.claimNotification(tx, {
                policyId: policy.id,
                userId: policy.user_id,
                kind: 'read_by_grantee',
                channel: this.notifier.channel,
                at: this.clock(),
              });

          return { ownerUserId: policy.user_id, rows, claimId };
        }),
    );

    if (outcome.claimId) {
      await this.sendClaimed(outcome.claimId, {
        kind: 'read_by_grantee',
        ownerUserId: outcome.ownerUserId,
        policyId,
      });
    }
    return { ownerUserId: outcome.ownerUserId, rows: outcome.rows };
  }

  /**
   * Send a notice whose record already exists, and fill in its outcome.
   *
   * The mirror image of `notify`, which sends first and records after. Both
   * treat a failed delivery the same way — a null `delivered_at`, never an
   * exception, because the read still happened and the owner still needs the
   * record — and both emit the unverified-recipient event on the same rule.
   */
  private async sendClaimed(
    notificationId: string,
    notification: EmergencyNotification,
  ): Promise<void> {
    let deliveredAt: Date | null = null;
    let recipientVerified = false;
    try {
      const sent = await this.notifier.notify(notification);
      deliveredAt = sent.delivered ? this.clock() : null;
      recipientVerified = sent.recipientVerified;
    } catch {
      // An adapter that broke its own contract. A non-delivery either way.
    }
    if (deliveredAt !== null) {
      await this.emergency.markNotificationDelivered(this.db, notificationId, deliveredAt);
    }
    if (deliveredAt !== null && !recipientVerified) {
      await this.events.audit.emit({
        action: 'vault.emergency.unverified_recipient',
        actorId: null,
        actorType: 'system',
        onBehalfOf: notification.ownerUserId,
        resourceType: 'vault',
        resourceId: notification.policyId,
        sessionId: null,
        detail: { kind: notification.kind },
      });
    }
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
    // Which act this gate is wrapping. Threaded through to the audit event
    // because all three used to look identical on the trail (PR3b review), and
    // required for the same reason `itemsListed`'s `scope` is: a fourth caller
    // must not be able to inherit somebody else's answer by omission.
    surface: 'request' | 'release' | 'read',
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
        surface,
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
