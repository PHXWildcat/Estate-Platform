import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import type { AuditAction } from '@estate/contracts';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * THIS SERVICE'S SLICE OF THE CLOSED VOCABULARY, DERIVED (M27 PR1b).
 *
 * This was twenty hand-written literals, and adding `vault.item.restored` is
 * what exposed the cost: the vocabulary in `@estate/contracts` already held
 * TWENTY-FOUR `vault.*` actions, so four members of the closed set were
 * unreachable from the one service that owns them — not by decision, but
 * because nobody re-typed them here. A producer cannot emit an action its own
 * parameter type has never heard of, and nothing was red.
 *
 * `Extract` makes the vocabulary the single source: a `vault.*` action added
 * to `AUDIT_ACTIONS` is emittable here the moment it exists, and one removed
 * stops compiling at every call site rather than at this list.
 */
type VaultAuditAction = Extract<AuditAction, `vault.${string}`>;

/**
 * The single egress point for this service's audit events.
 *
 * The PII firewall is trivially satisfied here and worth stating plainly: the
 * server cannot read a vault item even if it wanted to log one. What these
 * events carry is that an action happened, to which entity id, by whom - which
 * is exactly what docs/01 §6's vault-access-burst detection consumes.
 *
 * There is deliberately NO domain topic. No consumer exists for vault events
 * (the M3 rationale: topics appear when a consumer needs them), and a vault
 * payload on the bus is a category of risk with no current upside.
 */
@Injectable()
export class EventsService {
  readonly audit: AuditEmitter;

  constructor(@Inject(AUDIT_PRODUCER) producer: AuditProducer, @Inject(CLOCK) clock: Clock) {
    this.audit = new AuditEmitter(producer, clock);
  }

  private async emit(
    action: VaultAuditAction,
    input: {
      actorId: string;
      resourceType: 'vault' | 'vault_item' | 'vault_session' | 'emergency_access_policy';
      resourceId: string | null;
      sessionId?: string | null;
      onBehalfOf?: string | null;
      detail?: Record<string, string | number | boolean>;
    },
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId: input.actorId,
      actorType: 'user',
      onBehalfOf: input.onBehalfOf ?? null,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      sessionId: input.sessionId ?? null,
      detail: input.detail ?? {},
    });
  }

  async keysetCreated(userId: string, sessionId: string): Promise<void> {
    await this.emit('vault.keyset.created', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
    });
  }

  async keysetUpdated(
    userId: string,
    sessionId: string,
    detail: { revokedSessions: number },
  ): Promise<void> {
    await this.emit('vault.keyset.updated', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail,
    });
  }

  async opened(userId: string, sessionId: string, vaultSessionId: string): Promise<void> {
    await this.emit('vault.opened', {
      actorId: userId,
      resourceType: 'vault_session',
      resourceId: vaultSessionId,
      sessionId,
    });
  }

  /**
   * A failed unlock. `reason` is an enum token, never anything derived from the
   * attempt: the whole value of this event is that it is safe to emit on every
   * failure, which is what makes burst detection possible.
   */
  async openFailed(
    userId: string,
    sessionId: string,
    reason: 'bad_proof' | 'no_handshake' | 'no_keyset',
  ): Promise<void> {
    await this.emit('vault.open.failed', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail: { reason },
    });
  }

  /**
   * A LIST OF BLOBS WENT OUT, AND `scope` SAYS WHICH LIST (M27 PR1b).
   *
   * Both readers hand the caller whole ciphertexts, so both are disclosures and
   * both record. They are not the same disclosure: one enumerates what the user
   * has, the other enumerates what the user DELETED and has not got back. An
   * investigator reading `vault.items.listed` needs to tell those apart, and
   * `resourceId` cannot say it — it is the user in both cases.
   *
   * `scope` is a required argument rather than an optional one with a default,
   * so a third list route cannot inherit "live" by saying nothing. It stays
   * inside `AUDIT_ACTIONS`' existing member deliberately: a new action id is a
   * closed-vocabulary change that an older consumer drops silently, and this
   * distinction is a property OF the event, not a different event.
   */
  async itemsListed(
    userId: string,
    sessionId: string,
    count: number,
    scope: 'live' | 'restorable',
  ): Promise<void> {
    await this.emit('vault.items.listed', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail: { count, scope },
    });
  }

  async itemCreated(
    userId: string,
    sessionId: string,
    itemId: string,
    itemType: string,
  ): Promise<void> {
    await this.emit('vault.item.created', {
      actorId: userId,
      resourceType: 'vault_item',
      resourceId: itemId,
      sessionId,
      detail: { itemType },
    });
  }

  async itemAccessed(userId: string, sessionId: string, itemId: string): Promise<void> {
    await this.emit('vault.item.accessed', {
      actorId: userId,
      resourceType: 'vault_item',
      resourceId: itemId,
      sessionId,
    });
  }

  async itemUpdated(
    userId: string,
    sessionId: string,
    itemId: string,
    blobVersion: number,
  ): Promise<void> {
    await this.emit('vault.item.updated', {
      actorId: userId,
      resourceType: 'vault_item',
      resourceId: itemId,
      sessionId,
      detail: { blobVersion },
    });
  }

  async itemDeleted(userId: string, sessionId: string, itemId: string): Promise<void> {
    await this.emit('vault.item.deleted', {
      actorId: userId,
      resourceType: 'vault_item',
      resourceId: itemId,
      sessionId,
    });
  }

  /**
   * THE FIRST PRODUCER OF `vault.item.restored` (M27 PR1b). The action has been
   * in the closed vocabulary since PR0 with nothing emitting it.
   *
   * ONE ACTION, TWO SHAPES, discriminated by `kind` in the detail rather than
   * by a second action id. `AUDIT_ACTIONS` is a closed vocabulary and a
   * consumer that predates a member drops every instance of it silently, so a
   * new member costs a consumer deploy ahead of its producer; a detail token
   * costs nothing and answers the same question. The two arms are genuinely one
   * event — an item the owner could not use is one they can — and they differ
   * in what was put back, which is what the detail says.
   *
   * `version_seq` APPEARS NOWHERE. It is the shadow table's platform-wide
   * BIGINT identity; `revision` answers "which image" per item and is already
   * the client's own token.
   */
  async itemRestored(
    userId: string,
    sessionId: string,
    itemId: string,
    detail:
      | { kind: 'undelete'; revision: number }
      | { kind: 'version'; fromRevision: number; revision: number; blobVersion: number },
  ): Promise<void> {
    await this.emit('vault.item.restored', {
      actorId: userId,
      resourceType: 'vault_item',
      resourceId: itemId,
      sessionId,
      detail,
    });
  }

  async reset(
    userId: string,
    sessionId: string,
    detail: {
      itemsDestroyed: number;
      revokedSessions: number;
      /** Escrow policies torn down with the master key they wrapped. */
      escrowPoliciesRetired: number;
      /**
       * Rows that were ALREADY retired and are now relabelled `vault_reset`,
       * because this reset killed the key that would have opened them (M27
       * PR1b). Counted separately from `itemsDestroyed`: those were live a
       * moment ago and this reset retired them, while these were retired by
       * their owner earlier and only their DECRYPTABILITY changed here.
       */
      itemsRelabelled: number;
    },
  ): Promise<void> {
    await this.emit('vault.reset', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail,
    });
  }

  async sessionRevoked(
    userId: string,
    sessionId: string,
    vaultSessionId: string,
    reason: 'locked' | 'keyset_rotated' | 'vault_reset',
  ): Promise<void> {
    await this.emit('vault.session.revoked', {
      actorId: userId,
      resourceType: 'vault_session',
      resourceId: vaultSessionId,
      sessionId,
      detail: { reason },
    });
  }

  // --- emergency access (docs/03 §5.2) ---
  //
  // Every transition is recorded, including refusals. docs/03 §5.2 promises the
  // owner a "full audit visible to owner afterward", and a grantee who tried
  // repeatedly and was blocked each time is the single most important thing
  // that trail can show.

  async recoveryKeyPublished(userId: string, sessionId: string): Promise<void> {
    await this.emit('vault.recovery_key.published', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
    });
  }

  async emergencyConfigured(
    userId: string,
    sessionId: string,
    detail: { grantees: number; threshold: number },
  ): Promise<void> {
    await this.emit('vault.emergency.configured', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail,
    });
  }

  async emergencyRequested(
    granteeUserId: string,
    sessionId: string,
    policyId: string,
    detail: { waitingPeriodHours: number },
  ): Promise<void> {
    await this.emit('vault.emergency.requested', {
      actorId: granteeUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
      detail,
    });
  }

  async emergencyRequestBlocked(
    granteeUserId: string,
    sessionId: string,
    policyId: string,
    reason: string,
  ): Promise<void> {
    await this.emit('vault.emergency.request_blocked', {
      actorId: granteeUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
      detail: { reason },
    });
  }

  async emergencyDenied(ownerUserId: string, sessionId: string, policyId: string): Promise<void> {
    await this.emit('vault.emergency.denied', {
      actorId: ownerUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
    });
  }

  async emergencyRearmed(ownerUserId: string, sessionId: string, policyId: string): Promise<void> {
    await this.emit('vault.emergency.rearmed', {
      actorId: ownerUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
    });
  }

  async emergencyRevoked(ownerUserId: string, sessionId: string, policyId: string): Promise<void> {
    await this.emit('vault.emergency.revoked', {
      actorId: ownerUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
    });
  }

  /**
   * The docs/03 §6a gate refused: the owner's estate is in settlement and its
   * `vault` stage is not approved (or settlement was unreachable, which fails
   * closed the same way). Recorded even though nothing was written — a grantee
   * probing a settled estate is exactly what the estate needs visible.
   */
  /**
   * THE SETTLEMENT GATE REFUSED A GRANTEE, AND `surface` SAYS AT WHAT.
   *
   * The gate wraps three different acts — asking for access, collecting the
   * recovery key, and (M27 PR3b) READING the vault — and until PR3b's review
   * all three produced a byte-identical event: same action id, same actorId,
   * same `resourceType`/`resourceId`, same `detail`. So a grantee's reading
   * screen refetching produced events an investigator could not tell from a
   * grantee hammering the release route, which is the probing signal this
   * event exists to make visible. Ordinary reading noise must not be
   * indistinguishable from that.
   *
   * `surface` is REQUIRED, exactly as `itemsListed`'s `scope` is and for the
   * same reason: a fourth act put behind this gate cannot inherit a wrong
   * answer by saying nothing. It stays inside the existing `AUDIT_ACTIONS`
   * member for that reason too — a new action id is a closed-vocabulary change
   * an older consumer drops silently, and this is a property OF the refusal
   * rather than a different refusal.
   */
  async emergencyReleaseBlocked(
    granteeUserId: string,
    sessionId: string,
    policyId: string,
    caseId: string | null,
    surface: 'request' | 'release' | 'read',
  ): Promise<void> {
    await this.emit('vault.emergency.release_blocked', {
      actorId: granteeUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
      detail: caseId
        ? { reason: 'settlement_stage_not_reached', caseId, surface }
        : { reason: 'settlement_unavailable', surface },
    });
  }

  /**
   * A RELEASED GRANTEE READ THE OWNER'S ITEMS (M27 PR3b) — the first producer
   * for `vault.emergency.items_read`, which `packages/contracts/src/audit.ts`
   * has declared with no caller since M27 PR0.
   *
   * ON THE OWNER'S TRAIL, WITH THE GRANTEE AS ACTOR. `resourceId` is the
   * OWNER's id and `onBehalfOf` names them too, because the question this event
   * answers is the owner's ("who opened my vault, and when"), not the grantee's.
   * The audit contract's comment warns that two of the four existing
   * `onBehalfOf` call sites emit through `audit.emit` directly rather than
   * through these helpers, so the field is set explicitly here and inherits
   * nothing.
   *
   * PER READ, unlike the `read_by_grantee` notification, which fires once per
   * collection. The two are deliberately out of step: the audit trail is the
   * complete record an investigator reads afterwards, and the notification is
   * an interrupt a living owner has to be able to act on. Making the trail
   * sparse to spare the mailbox would trade the wrong one away.
   */
  async emergencyItemsRead(
    granteeUserId: string,
    sessionId: string,
    policyId: string,
    ownerUserId: string,
    detail: { count: number; scope: 'live' | 'item' },
  ): Promise<void> {
    await this.emit('vault.emergency.items_read', {
      actorId: granteeUserId,
      resourceType: 'vault',
      resourceId: ownerUserId,
      sessionId,
      onBehalfOf: ownerUserId,
      detail: { ...detail, policyId },
    });
  }

  async emergencyReleased(
    granteeUserId: string,
    sessionId: string,
    policyId: string,
    ownerUserId: string,
  ): Promise<void> {
    await this.emit('vault.emergency.released', {
      actorId: granteeUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
      // onBehalfOf is what makes this event legible: a grantee acted, and the
      // vault it reached belongs to someone else.
      onBehalfOf: ownerUserId,
    });
  }
}
