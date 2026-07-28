import { Injectable } from '@nestjs/common';
import { Db } from './db';

export interface RoleAssignmentRow {
  id: string;
  owner_user_id: string;
  contact_id: string;
  role: string;
  scope_type: string;
  scope_id: string | null;
  effective_condition: string;
  starts_at: Date | null;
  ends_at: Date | null;
}

export interface RoleAssignmentInsert {
  ownerUserId: string;
  contactId: string;
  role: string;
  scopeType: string;
  scopeId: string | null;
  effectiveCondition: string;
  startsAt: Date | null;
  endsAt: Date | null;
}

/** An effective grant row: the scope of a role_assignment carrying a read grant. */
export interface EffectiveGrant {
  scope_type: string;
  scope_id: string | null;
}

@Injectable()
export class RolesRepo {
  constructor(private readonly db: Db) {}

  /**
   * Whether the co-tenant settlement service's `settlement_cases` table exists
   * in this database (M7). Profile and settlement share the core cluster with
   * disjoint tables, but they deploy independently: profile must keep working
   * against a cluster where settlement's migrations have not run (and in
   * profile's own scratch-schema tests, where they never run). A missing table
   * means settlement has never existed here, so no case can exist and the
   * grant freeze is vacuously satisfied.
   *
   * ONLY THE POSITIVE IS CACHED. The M7 security review found the original
   * memoised a NEGATIVE for the process lifetime: a profile process that
   * started before settlement's migration ran would compile the freeze out of
   * its SQL permanently and silently, so docs/03 §5.1 control 4 ("reads freeze
   * for role-holders") would never engage for that process even once cases
   * existed — a fail-OPEN indistinguishable from a working freeze. The table
   * cannot disappear once created, so caching `true` forever is sound; `false`
   * is re-probed. The cost is one `to_regclass` per grant resolution, and only
   * until settlement deploys.
   */
  private settlementCasesPresent = false;

  private async hasSettlementCases(): Promise<boolean> {
    if (this.settlementCasesPresent) {
      return true;
    }
    const rows = await this.db.query<{ present: string | null }>(
      `SELECT to_regclass('settlement_cases')::text AS present`,
    );
    this.settlementCasesPresent = (rows[0]?.present ?? null) !== null;
    return this.settlementCasesPresent;
  }

  async insert(input: RoleAssignmentInsert): Promise<string> {
    const rows = await this.db.query<{ id: string }>(
      `INSERT INTO role_assignments
         (owner_user_id, contact_id, role, scope_type, scope_id, effective_condition, starts_at, ends_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id`,
      [
        input.ownerUserId,
        input.contactId,
        input.role,
        input.scopeType,
        input.scopeId,
        input.effectiveCondition,
        input.startsAt,
        input.endsAt,
      ],
    );
    return (rows[0] as { id: string }).id;
  }

  async listByOwner(ownerUserId: string): Promise<RoleAssignmentRow[]> {
    return this.db.query<RoleAssignmentRow>(
      `SELECT id, owner_user_id, contact_id, role, scope_type, scope_id,
              effective_condition, starts_at, ends_at
         FROM role_assignments
        WHERE owner_user_id = $1 AND deleted_at IS NULL
        ORDER BY created_at`,
      [ownerUserId],
    );
  }

  async findById(id: string): Promise<RoleAssignmentRow | null> {
    const rows = await this.db.query<RoleAssignmentRow>(
      `SELECT id, owner_user_id, contact_id, role, scope_type, scope_id,
              effective_condition, starts_at, ends_at
         FROM role_assignments
        WHERE id = $1 AND deleted_at IS NULL`,
      [id],
    );
    return rows[0] ?? null;
  }

  async revoke(id: string, ownerUserId: string): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE role_assignments SET deleted_at = now()
        WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
        RETURNING id`,
      [id, ownerUserId],
    );
    return rows.length > 0;
  }

  /**
   * Resolve the EFFECTIVE read grants a caller holds over an owner's contacts.
   * A grant is effective when: the caller is the platform user linked to the
   * granted contact, the role_assignment is live and immediate, we are inside
   * its [starts_at, ends_at) window, and it carries a live `contact`/`read`
   * permission_grant. Returns each such assignment's scope so the caller can
   * decide which specific resources are named (scope_id) vs. estate-wide
   * (scope_type='estate', scope_id NULL). This is the docs/03 §5.5 boundary.
   *
   * M7 (docs/03 §5.1 control 4: "reads freeze for role-holders"): while the
   * owner has a settlement case at or past its waiting period, every grant
   * this query would confer is suspended — the settlement flow, not standing
   * grants, is the only access path to a possibly-deceased owner's data.
   * 'reported'/'verifying' cases do NOT freeze: an unreviewed report must not
   * strip a living owner's contacts of their granted access.
   */
  async effectiveContactReadGrants(
    ownerUserId: string,
    callerUserId: string,
    now: Date,
  ): Promise<EffectiveGrant[]> {
    const freezePredicate = (await this.hasSettlementCases())
      ? `AND NOT EXISTS (
           SELECT 1 FROM settlement_cases sc
            WHERE sc.decedent_user_id = ra.owner_user_id
              AND sc.status IN ('waiting_period','verified','active','distributing')
         )`
      : '';
    return this.db.query<EffectiveGrant>(
      `SELECT DISTINCT ra.scope_type, ra.scope_id
         FROM role_assignments ra
         JOIN contacts c
           ON c.id = ra.contact_id AND c.deleted_at IS NULL
         JOIN permission_grants pg
           ON pg.role_assignment_id = ra.id
        WHERE ra.owner_user_id = $1
          AND c.linked_user_id = $2
          AND ra.deleted_at IS NULL
          AND ra.effective_condition = 'immediate'
          AND (ra.starts_at IS NULL OR ra.starts_at <= $3)
          AND (ra.ends_at IS NULL OR ra.ends_at > $3)
          AND pg.revoked_at IS NULL
          AND pg.resource = 'contact'
          AND pg.action = 'read'
          ${freezePredicate}`,
      [ownerUserId, callerUserId, now],
    );
  }
}

@Injectable()
export class PermissionGrantsRepo {
  constructor(private readonly db: Db) {}

  async insert(
    roleAssignmentId: string,
    resource: string,
    action: string,
    constraintExpr: Record<string, unknown> | null,
  ): Promise<string> {
    const rows = await this.db.query<{ id: string }>(
      `INSERT INTO permission_grants (role_assignment_id, resource, action, constraint_expr)
       VALUES ($1,$2,$3,$4)
       RETURNING id`,
      [
        roleAssignmentId,
        resource,
        action,
        constraintExpr === null ? null : JSON.stringify(constraintExpr),
      ],
    );
    return (rows[0] as { id: string }).id;
  }

  async listByRoleAssignment(
    roleAssignmentId: string,
  ): Promise<Array<{ id: string; resource: string; action: string }>> {
    return this.db.query<{ id: string; resource: string; action: string }>(
      `SELECT id, resource, action
         FROM permission_grants
        WHERE role_assignment_id = $1 AND revoked_at IS NULL
        ORDER BY created_at`,
      [roleAssignmentId],
    );
  }
}
