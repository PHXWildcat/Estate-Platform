import { Injectable } from '@nestjs/common';
import { Db } from './db';

export interface ReportableEstate {
  decedentUserId: string;
  contactId: string;
  /** Role tokens from the decedent's role_assignments naming this contact. */
  roles: string[];
}

/**
 * READ-ONLY access to the profile service's core-cluster tables (contacts,
 * role_assignments) — the flagged extension of the Plaid co-tenancy precedent
 * (docs/02 §7 places settlement in core precisely because its rows reference
 * core contacts). Settlement never writes these tables; in production the
 * service's DB role gets SELECT only.
 *
 * These queries are the anti-enumeration boundary of intake (docs/03 §5.1
 * control 6 + §5.5): a reporter can only act on estates that already NAME
 * them via contacts.linked_user_id — there is no lookup by email or by
 * arbitrary user id anywhere in this service.
 */
@Injectable()
export class CoreReadsRepo {
  constructor(private readonly db: Db) {}

  /** Is `userId` the linked platform user of a live contact of `decedent`? */
  async isLinkedContact(decedentUserId: string, userId: string): Promise<boolean> {
    const rows = await this.db.query<{ ok: number }>(
      `SELECT 1 AS ok
         FROM contacts
        WHERE owner_user_id = $1
          AND linked_user_id = $2
          AND deleted_at IS NULL
        LIMIT 1`,
      [decedentUserId, userId],
    );
    return rows.length > 0;
  }

  /** Estates whose contact repository names the caller (IDs and role tokens only). */
  async reportableEstates(userId: string): Promise<ReportableEstate[]> {
    const rows = await this.db.query<{
      owner_user_id: string;
      contact_id: string;
      roles: string[] | null;
    }>(
      `SELECT c.owner_user_id,
              c.id AS contact_id,
              array_remove(array_agg(DISTINCT ra.role), NULL) AS roles
         FROM contacts c
         LEFT JOIN role_assignments ra
           ON ra.contact_id = c.id AND ra.deleted_at IS NULL
        WHERE c.linked_user_id = $1
          AND c.deleted_at IS NULL
        GROUP BY c.owner_user_id, c.id`,
      [userId],
    );
    return rows.map((r) => ({
      decedentUserId: r.owner_user_id,
      contactId: r.contact_id,
      roles: r.roles ?? [],
    }));
  }
}
