import { Injectable } from '@nestjs/common';
import { isConsentScope, type ConsentScope } from './consent';
// `Db` is a VALUE import because it is a constructor dependency: an
// `import type` erases at runtime, leaving Nest's design:paramtypes metadata
// undefined and the provider unresolvable at boot. `Queryable` is a pure type.
import { Db, type Queryable } from './db';

interface ScopeRow {
  scope: string;
}

interface IdRow {
  id: string;
}

/**
 * Consent storage. Modeled on profile's `permission_grants`: append + revoke,
 * no soft delete and no versions shadow table — the rows themselves are the
 * history, and a consent is an access record that is revoked, never deleted.
 *
 * Reads and writes are deliberately asymmetric in shape: `grantedScopes` is the
 * hot path consulted on every tool invocation and takes the pool directly,
 * while `grant` and `revoke` take a `Queryable` so the caller can run them
 * inside the transaction that also emits their audit event.
 */
@Injectable()
export class ConsentsRepo {
  constructor(private readonly db: Db) {}

  /**
   * The user's currently granted scopes. An unrevoked row is the ONLY
   * affirmative state, so a user who has never answered yields an empty set —
   * the deny-by-default posture falls out of the query rather than being
   * layered on top of it.
   *
   * A stored scope this build does not recognise is DROPPED rather than
   * trusted. The database can be ahead of the code during a rollback or a
   * partial deploy, and in that window an unknown scope is an unknown grant;
   * the safe reading of an unknown grant is no grant.
   */
  async grantedScopes(userId: string): Promise<Set<ConsentScope>> {
    const rows = await this.db.query<ScopeRow>(
      `SELECT scope
         FROM assistant_consents
        WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId],
    );
    const granted = new Set<ConsentScope>();
    for (const row of rows) {
      if (isConsentScope(row.scope)) {
        granted.add(row.scope);
      }
    }
    return granted;
  }

  /**
   * Grant a scope. Idempotent by way of the partial unique index: re-granting
   * a live scope is a no-op rather than a second row, so "is this granted?"
   * can never be ambiguous and a revoke can never leave a shadow grant behind.
   * Returns true only when a row was actually created, which is what the
   * caller audits — a no-op re-grant is not a consent change.
   */
  async grant(
    tx: Queryable,
    userId: string,
    scope: ConsentScope,
    grantedBy: string,
  ): Promise<boolean> {
    const rows = await tx.query<IdRow>(
      `INSERT INTO assistant_consents (user_id, scope, granted_by)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, scope) WHERE revoked_at IS NULL DO NOTHING
       RETURNING id`,
      [userId, scope, grantedBy],
    );
    return rows.length > 0;
  }

  /**
   * Revoke a scope. Returns true only when a live grant was actually retired,
   * so revoking something already revoked is reported as the no-op it is.
   */
  async revoke(
    tx: Queryable,
    userId: string,
    scope: ConsentScope,
    revokedBy: string,
  ): Promise<boolean> {
    const rows = await tx.query<IdRow>(
      `UPDATE assistant_consents
          SET revoked_at = now(), revoked_by = $3
        WHERE user_id = $1 AND scope = $2 AND revoked_at IS NULL
        RETURNING id`,
      [userId, scope, revokedBy],
    );
    return rows.length > 0;
  }
}
