import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';
import type { EmergencyNotificationKind } from './notifications';

export type PolicyStatus =
  'configured' | 'requested' | 'waiting' | 'denied_by_owner' | 'released' | 'revoked';

export interface EscrowConfigRow {
  user_id: string;
  threshold: number;
  platform_part: Buffer;
  wrapped_master_key_recovery: Buffer;
  /** M27 PR3b: what a grantee reads instead of `user_id`. Null before PR3b. */
  label: string | null;
  created_at: Date;
  updated_at: Date;
}

/** A policy as the GRANTEE sees it: their row, plus the owner's label. */
export interface GranteePolicyRow extends PolicyRow {
  owner_label: string | null;
}

export interface PolicyRow {
  id: string;
  user_id: string;
  grantee_contact_id: string;
  grantee_user_id: string;
  waiting_period_hours: number;
  key_share_ct: Buffer;
  grantee_public_key_sha256: Buffer;
  status: PolicyStatus;
  requested_at: Date | null;
  releases_at: Date | null;
  denied_at: Date | null;
  released_at: Date | null;
  revoked_at: Date | null;
  request_count: number;
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
}

const POLICY_COLUMNS = `id, user_id, grantee_contact_id, grantee_user_id, waiting_period_hours,
  key_share_ct, grantee_public_key_sha256, status, requested_at, releases_at, denied_at,
  released_at, revoked_at, request_count, created_at, updated_at, deleted_at`;

/**
 * The same columns, qualified with the `p` alias for the one query that joins.
 * DERIVED from POLICY_COLUMNS rather than a second hand-written list: a column
 * added above must not be able to arrive in one reader and not the other.
 */
const POLICY_COLUMNS_P = POLICY_COLUMNS.replace(/([A-Za-z_][A-Za-z0-9_]*)/g, 'p.$1');

const CONFIG_COLUMNS = `user_id, threshold, platform_part, wrapped_master_key_recovery, label, created_at, updated_at`;

@Injectable()
export class EmergencyRepo {
  // --- escrow config (owner level) ---

  async findConfig(q: Queryable | Db, userId: string): Promise<EscrowConfigRow | null> {
    const rows = await q.query<EscrowConfigRow>(
      `SELECT ${CONFIG_COLUMNS} FROM emergency_access_configs WHERE user_id = $1`,
      [userId],
    );
    return rows[0] ?? null;
  }

  async lockConfig(tx: Queryable, userId: string): Promise<EscrowConfigRow | null> {
    const rows = await tx.query<EscrowConfigRow>(
      `SELECT ${CONFIG_COLUMNS} FROM emergency_access_configs WHERE user_id = $1 FOR UPDATE`,
      [userId],
    );
    return rows[0] ?? null;
  }

  /** Configure replaces wholesale: one escrow per owner, never a merge. */
  async upsertConfig(
    tx: Queryable,
    input: {
      userId: string;
      threshold: number;
      platformPart: Buffer;
      wrappedMasterKeyRecovery: Buffer;
      /**
       * M27 PR3b. WRITTEN ON EVERY CONFIGURE, including when absent — the
       * EXCLUDED clause sets it to null rather than leaving the previous one
       * standing. Configure replaces an escrow wholesale (it retires every
       * prior policy and sends `grantees_changed`), so a label surviving into
       * an arrangement the owner rebuilt without one would be the old escrow's
       * name on the new escrow's grantee rows.
       */
      label: string | null;
    },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO emergency_access_configs
         (user_id, threshold, platform_part, wrapped_master_key_recovery, label)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id) DO UPDATE
         SET threshold = EXCLUDED.threshold,
             platform_part = EXCLUDED.platform_part,
             wrapped_master_key_recovery = EXCLUDED.wrapped_master_key_recovery,
             label = EXCLUDED.label`,
      [
        input.userId,
        input.threshold,
        input.platformPart,
        input.wrappedMasterKeyRecovery,
        input.label,
      ],
    );
  }

  async deleteConfig(tx: Queryable, userId: string): Promise<void> {
    await tx.query(`DELETE FROM emergency_access_configs WHERE user_id = $1`, [userId]);
  }

  // --- policies (per grantee) ---

  async listByOwner(q: Queryable | Db, userId: string): Promise<PolicyRow[]> {
    return q.query<PolicyRow>(
      `SELECT ${POLICY_COLUMNS} FROM emergency_access_policies
        WHERE user_id = $1 AND deleted_at IS NULL
        -- id breaks the tie: configure inserts every policy in ONE transaction,
        -- so created_at is identical across them and ordering by it alone is
        -- not deterministic.
        ORDER BY created_at, id`,
      [userId],
    );
  }

  /**
   * The grantee's own list, joined to the owner's LABEL (M27 PR3b).
   *
   * A LEFT join, and it stays left even though `configure` writes both rows in
   * one transaction: `deleteConfig` exists, so a policy outliving its config is
   * a state this schema can reach, and an inner join would answer "you were
   * never named" to a grantee whose arrangement merely lost its escrow. The
   * fallback for a missing label and a missing config is the same — null, and
   * the reading surface prints the owner's id, exactly as it did before PR3b.
   */
  async listByGrantee(q: Queryable | Db, granteeUserId: string): Promise<GranteePolicyRow[]> {
    return q.query<GranteePolicyRow>(
      `SELECT ${POLICY_COLUMNS_P}, c.label AS owner_label
         FROM emergency_access_policies p
         LEFT JOIN emergency_access_configs c ON c.user_id = p.user_id
        WHERE p.grantee_user_id = $1 AND p.deleted_at IS NULL
        -- id breaks the tie: configure inserts every policy in ONE transaction,
        -- so created_at is identical across them and ordering by it alone is
        -- not deterministic.
        ORDER BY p.created_at, p.id`,
      [granteeUserId],
    );
  }

  /**
   * Every grantee currently HOLDING a released collection on this owner's
   * escrow (M27 PR3b).
   *
   * This is the set `vault.cedar` evaluates `emergencyGrantees.contains` over,
   * and it is read from the table rather than assembled from the caller's own
   * id on purpose. Passing `[granteeUserId]` would have made the Cedar
   * decision a tautology — a gate that cannot deny is a gate that cannot be
   * shown to work — whereas this set is derived from `status`, so a policy the
   * owner stopped drops out of it and the PDP is what refuses.
   */
  async listReleasedGranteeIds(q: Queryable | Db, ownerUserId: string): Promise<string[]> {
    const rows = await q.query<{ grantee_user_id: string }>(
      `SELECT grantee_user_id FROM emergency_access_policies
        WHERE user_id = $1 AND status = 'released' AND deleted_at IS NULL
        ORDER BY grantee_user_id`,
      [ownerUserId],
    );
    return rows.map((row) => row.grantee_user_id);
  }

  /**
   * Lock a policy BY (id, owner) together, so "no such policy" and "not your
   * policy" are one empty result.
   *
   * `requireGranteePolicy` has always answered a uniform 404 for the grantee
   * arm, and says why in its own comment; `requireOwnerPolicy` twelve lines
   * above it read by id alone and let `assertCan` answer `403 forbidden`, so
   * the two halves of one refusal had two spellings and only one of them was
   * right. M27 PR1a, applying the same fusion it applied to `vault_items`.
   */
  /** The grantee arm of the same rule: (id, grantee) fused into one lookup. */
  async lockLiveByIdForGrantee(
    tx: Queryable,
    id: string,
    granteeUserId: string,
  ): Promise<PolicyRow | null> {
    const rows = await tx.query<PolicyRow>(
      `SELECT ${POLICY_COLUMNS} FROM emergency_access_policies
        WHERE id = $1 AND grantee_user_id = $2 AND deleted_at IS NULL FOR UPDATE`,
      [id, granteeUserId],
    );
    return rows[0] ?? null;
  }

  async lockLiveByIdForOwner(
    tx: Queryable,
    id: string,
    ownerUserId: string,
  ): Promise<PolicyRow | null> {
    const rows = await tx.query<PolicyRow>(
      `SELECT ${POLICY_COLUMNS} FROM emergency_access_policies
        WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL FOR UPDATE`,
      [id, ownerUserId],
    );
    return rows[0] ?? null;
  }

  /** Retire every live policy for an owner, so configure is a clean replace. */
  async softDeleteAllForOwner(tx: Queryable, userId: string, at: Date): Promise<number> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE emergency_access_policies SET deleted_at = $2
        WHERE user_id = $1 AND deleted_at IS NULL
        RETURNING id`,
      [userId, at],
    );
    return rows.length;
  }

  async insertPolicy(
    tx: Queryable,
    input: {
      userId: string;
      granteeContactId: string;
      granteeUserId: string;
      waitingPeriodHours: number;
      keyShare: Buffer;
      granteePublicKeySha256: Buffer;
    },
  ): Promise<PolicyRow> {
    const rows = await tx.query<PolicyRow>(
      `INSERT INTO emergency_access_policies
         (user_id, grantee_contact_id, grantee_user_id, waiting_period_hours,
          key_share_ct, grantee_public_key_sha256)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING ${POLICY_COLUMNS}`,
      [
        input.userId,
        input.granteeContactId,
        input.granteeUserId,
        input.waitingPeriodHours,
        input.keyShare,
        input.granteePublicKeySha256,
      ],
    );
    return rows[0]!;
  }

  /** Open the waiting period. */
  async markRequested(
    tx: Queryable,
    input: { id: string; at: Date; releasesAt: Date },
  ): Promise<PolicyRow> {
    const rows = await tx.query<PolicyRow>(
      `UPDATE emergency_access_policies
          SET status = 'waiting', requested_at = $2, releases_at = $3,
              request_count = request_count + 1
        WHERE id = $1
        RETURNING ${POLICY_COLUMNS}`,
      [input.id, input.at, input.releasesAt],
    );
    return rows[0]!;
  }

  /** Count a request that was refused, so a grinding grantee is visible. */
  async countBlockedRequest(tx: Queryable, id: string): Promise<void> {
    await tx.query(
      `UPDATE emergency_access_policies SET request_count = request_count + 1 WHERE id = $1`,
      [id],
    );
  }

  async markDenied(tx: Queryable, id: string, at: Date): Promise<PolicyRow> {
    const rows = await tx.query<PolicyRow>(
      `UPDATE emergency_access_policies
          SET status = 'denied_by_owner', denied_at = $2, releases_at = NULL
        WHERE id = $1
        RETURNING ${POLICY_COLUMNS}`,
      [id, at],
    );
    return rows[0]!;
  }

  /** Owner clears a denial and makes the policy usable again. */
  async markRearmed(tx: Queryable, id: string): Promise<PolicyRow> {
    const rows = await tx.query<PolicyRow>(
      `UPDATE emergency_access_policies
          SET status = 'configured', denied_at = NULL, requested_at = NULL,
              releases_at = NULL, request_count = 0
        WHERE id = $1
        RETURNING ${POLICY_COLUMNS}`,
      [id],
    );
    return rows[0]!;
  }

  async markReleased(tx: Queryable, id: string, at: Date): Promise<PolicyRow> {
    const rows = await tx.query<PolicyRow>(
      `UPDATE emergency_access_policies
          SET status = 'released', released_at = $2
        WHERE id = $1
        RETURNING ${POLICY_COLUMNS}`,
      [id, at],
    );
    return rows[0]!;
  }

  async markRevoked(tx: Queryable, id: string, at: Date): Promise<PolicyRow> {
    const rows = await tx.query<PolicyRow>(
      `UPDATE emergency_access_policies
          SET status = 'revoked', revoked_at = $2, releases_at = NULL, deleted_at = $2
        WHERE id = $1
        RETURNING ${POLICY_COLUMNS}`,
      [id, at],
    );
    return rows[0]!;
  }

  // --- notification record ---

  async recordNotification(
    q: Queryable | Db,
    input: {
      /** Null for vault-level kinds ('reset') that outlive every policy. */
      policyId: string | null;
      userId: string;
      kind: EmergencyNotificationKind;
      channel: string;
      deliveredAt: Date | null;
    },
  ): Promise<void> {
    await q.query(
      `INSERT INTO emergency_access_notifications (policy_id, user_id, kind, channel, delivered_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [input.policyId, input.userId, input.kind, input.channel, input.deliveredAt],
    );
  }

  /**
   * HAS THE OWNER ALREADY BEEN TOLD ABOUT *THIS* COLLECTION? (M27 PR3b)
   *
   * `vault.read_by_grantee` is emitted once per COLLECTION, not once per read,
   * and this row is the whole mechanism — there is no `notified` flag on the
   * policy. That is deliberate: M27 PR3a made release re-collectable, and a
   * stored flag would have to be reset by every writer that moves a policy out
   * of `released` — `markDenied` and `markRevoked` — plus the one that puts it
   * back, `markReleased`. THREE, not the four an earlier draft of this comment
   * claimed: `markRearmed` never sees a released policy, because `rearm`
   * refuses one with `already_released` before reaching the repo. That is a
   * fact about a guard in another file, so it is pinned by a test
   * (`refuses to re-arm a policy that has already been collected`) rather than
   * asserted here — the earlier count was wrong precisely because nothing
   * checked it. Three writers to keep in step, versus a predicate that re-arms
   * by itself because `released_at` moves forward on every collection.
   *
   * INSIDE THE CALLER'S TRANSACTION, and the caller takes the policy row `FOR
   * UPDATE` first: two concurrent first-reads would otherwise both see no row
   * and both notify.
   *
   * DELIBERATELY BLIND TO `delivered_at`. An ATTEMPT suppresses the next
   * attempt, so a dead channel cannot turn one grantee's reading session into
   * a message per item. The cost is real and is recorded in docs/06: a
   * `read_by_grantee` that fails to send is not retried on the next read, and
   * the owner's only remaining signal for that collection is the
   * `emergency.released` they were already sent.
   */
  async hasNotifiedSince(
    q: Queryable | Db,
    input: { policyId: string; kind: EmergencyNotificationKind; since: Date },
  ): Promise<boolean> {
    const rows = await q.query<{ hit: boolean }>(
      `SELECT true AS hit FROM emergency_access_notifications
        WHERE policy_id = $1 AND kind = $2 AND created_at >= $3
        LIMIT 1`,
      [input.policyId, input.kind, input.since],
    );
    return rows.length > 0;
  }

  /**
   * CLAIM the once-per-collection slot, INSIDE the caller's transaction.
   *
   * `notify()` sends first and records after, which is right for every other
   * kind: the record carries the delivery outcome, and nothing reads it back.
   * `read_by_grantee` DOES read it back — `hasNotifiedSince` above is its
   * whole dedupe — so a decide-here/record-later split would leave the check
   * and the write in different transactions and the policy lock would protect
   * nothing. Two grantee reads racing the first collection would each find no
   * row and each send.
   *
   * So the row is written while the policy is still locked FOR UPDATE, with a
   * null `delivered_at` that `markNotificationDelivered` fills in afterwards.
   * The row means "this collection's notice is claimed", and the outcome
   * column means what it means everywhere else.
   *
   * `created_at` IS WRITTEN EXPLICITLY, FROM THE SERVICE CLOCK, and every other
   * writer on this table lets the column default to `now()`. That difference is
   * the point: `hasNotifiedSince` compares this value against `released_at`,
   * which the service sets from its OWN clock — so defaulting here would put a
   * DB-server timestamp and an app-server timestamp on the two sides of one
   * predicate. Any skew between them is a duplicate notice or a missing one,
   * and the direction depends on which way the clocks drift. The integration
   * suite found it the loud way, by simulating a waiting period: `released_at`
   * was 2027 and `now()` was not, so the dedupe read as "never told" on every
   * single read.
   */
  async claimNotification(
    tx: Queryable,
    input: {
      policyId: string;
      userId: string;
      kind: EmergencyNotificationKind;
      channel: string;
      at: Date;
    },
  ): Promise<string> {
    const rows = await tx.query<{ id: string }>(
      `INSERT INTO emergency_access_notifications
         (policy_id, user_id, kind, channel, delivered_at, created_at)
       VALUES ($1, $2, $3, $4, NULL, $5)
       RETURNING id`,
      [input.policyId, input.userId, input.kind, input.channel, input.at],
    );
    return rows[0]!.id;
  }

  /**
   * Fill in the outcome on a claimed row. Never clears it: a delivery that
   * failed leaves the null it was written with, which is the same signal
   * `recordNotification` produces for every other kind.
   */
  async markNotificationDelivered(q: Queryable | Db, id: string, at: Date): Promise<void> {
    await q.query(
      `UPDATE emergency_access_notifications SET delivered_at = $2
        WHERE id = $1 AND delivered_at IS NULL`,
      [id, at],
    );
  }

  async countNotifications(q: Queryable | Db, policyId: string): Promise<number> {
    const rows = await q.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM emergency_access_notifications WHERE policy_id = $1`,
      [policyId],
    );
    return Number(rows[0]?.count ?? '0');
  }
}
