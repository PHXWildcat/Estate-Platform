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
  created_at: Date;
  updated_at: Date;
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

const CONFIG_COLUMNS = `user_id, threshold, platform_part, wrapped_master_key_recovery, created_at, updated_at`;

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
    },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO emergency_access_configs
         (user_id, threshold, platform_part, wrapped_master_key_recovery)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO UPDATE
         SET threshold = EXCLUDED.threshold,
             platform_part = EXCLUDED.platform_part,
             wrapped_master_key_recovery = EXCLUDED.wrapped_master_key_recovery`,
      [input.userId, input.threshold, input.platformPart, input.wrappedMasterKeyRecovery],
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

  async listByGrantee(q: Queryable | Db, granteeUserId: string): Promise<PolicyRow[]> {
    return q.query<PolicyRow>(
      `SELECT ${POLICY_COLUMNS} FROM emergency_access_policies
        WHERE grantee_user_id = $1 AND deleted_at IS NULL
        -- id breaks the tie: configure inserts every policy in ONE transaction,
        -- so created_at is identical across them and ordering by it alone is
        -- not deterministic.
        ORDER BY created_at, id`,
      [granteeUserId],
    );
  }

  async findLiveById(q: Queryable | Db, id: string): Promise<PolicyRow | null> {
    const rows = await q.query<PolicyRow>(
      `SELECT ${POLICY_COLUMNS} FROM emergency_access_policies
        WHERE id = $1 AND deleted_at IS NULL`,
      [id],
    );
    return rows[0] ?? null;
  }

  async lockLiveById(tx: Queryable, id: string): Promise<PolicyRow | null> {
    const rows = await tx.query<PolicyRow>(
      `SELECT ${POLICY_COLUMNS} FROM emergency_access_policies
        WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
      [id],
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

  async countNotifications(q: Queryable | Db, policyId: string): Promise<number> {
    const rows = await q.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM emergency_access_notifications WHERE policy_id = $1`,
      [policyId],
    );
    return Number(rows[0]?.count ?? '0');
  }
}
