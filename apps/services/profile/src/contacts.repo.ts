import { Injectable } from '@nestjs/common';
import { Db } from './db';

/**
 * The owner-editable fields of a contact — and the shape both the INSERT and the
 * UPDATE below are built from.
 *
 * `linked_user_id` IS DELIBERATELY NOT HERE, and its absence is the fix for the
 * defect this type exists to make unrepresentable. One `encryptRow` fed both
 * statements while hardcoding `linked_user_id: null`, and the UPDATE wrote that
 * column, so editing a contact's phone number silently cleared the link. The
 * link is an authorization edge — it is what makes someone able to open a death
 * case (docs/03 §6b) and what makes an executor resolvable (M7) — so clearing it
 * as a side effect of an unrelated edit revokes a §5.1 control without an audit
 * event or an owner decision. Keeping the column out of this type means the
 * ordinary write path has no field in which to say anything about it: the
 * INSERT omits it (the column defaults NULL) and the UPDATE never names it.
 * A deliberate link ceremony writes it through its own statement.
 */
export interface ContactFields {
  name_ct: Buffer;
  email_ct: Buffer | null;
  email_bidx: Buffer | null;
  phone_ct: Buffer | null;
  address_ct: Buffer | null;
  relationship: string | null;
  professional_kind: string | null;
  notes_ct: Buffer | null;
  dek_id: string;
}

export interface ContactRow extends ContactFields {
  id: string;
  owner_user_id: string;
  linked_user_id: string | null;
}

export type ContactInsert = ContactFields & { owner_user_id: string };

@Injectable()
export class ContactsRepo {
  constructor(private readonly db: Db) {}

  async insert(row: ContactInsert): Promise<string> {
    const rows = await this.db.query<{ id: string }>(
      `INSERT INTO contacts (
         owner_user_id, name_ct, email_ct, email_bidx, phone_ct, address_ct,
         relationship, professional_kind, notes_ct, dek_id
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id`,
      [
        row.owner_user_id,
        row.name_ct,
        row.email_ct,
        row.email_bidx,
        row.phone_ct,
        row.address_ct,
        row.relationship,
        row.professional_kind,
        row.notes_ct,
        row.dek_id,
      ],
    );
    return (rows[0] as { id: string }).id;
  }

  /** Update the owner-editable fields. `linked_user_id` is never touched here. */
  async update(id: string, ownerUserId: string, row: ContactFields): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE contacts SET
         name_ct = $3, email_ct = $4, email_bidx = $5, phone_ct = $6, address_ct = $7,
         relationship = $8, professional_kind = $9, notes_ct = $10, dek_id = $11
        WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
        RETURNING id`,
      [
        id,
        ownerUserId,
        row.name_ct,
        row.email_ct,
        row.email_bidx,
        row.phone_ct,
        row.address_ct,
        row.relationship,
        row.professional_kind,
        row.notes_ct,
        row.dek_id,
      ],
    );
    return rows.length > 0;
  }

  /**
   * Soft-delete, REFUSING if a live role assignment names this contact — and
   * serialized against `grantRole` on the CONTACT ROW.
   *
   * TWO WRONG VERSIONS PRECEDED THIS ONE, which is why the reasoning is spelled
   * out. First the check lived in the service, plainly check-then-act. Then it
   * moved into this UPDATE's `WHERE` and was declared atomic — but a `WHERE NOT
   * EXISTS` over `role_assignments` locks the CONTACTS row, not the assignments
   * it reads, and the counterparty (`RolesService.grantRole`) was itself
   * check-then-act across two autocommit statements. Under concurrency the
   * interleaving still deleted a contact that had just acquired a designation:
   * the docs/03 §6f fail-open, with three places claiming it was closed.
   *
   * So both paths now take the same lock: `SELECT ... FOR UPDATE` on the contact
   * row inside one transaction. `grantRole` locks it before inserting an
   * assignment; this locks it before checking for assignments and deleting. Two
   * writers contending for one row is the only thing that actually orders them —
   * the same reason M7's owner-liveness interlock takes the users row lock.
   *
   * The discriminated outcome keeps "nothing to delete" (404) apart from "a
   * designation stands in the way" (409): different facts, different remedies.
   * Both are now decided INSIDE the transaction, so the answer cannot describe a
   * world that stopped existing between two statements.
   */
  async softDelete(id: string, ownerUserId: string): Promise<'deleted' | 'in_use' | 'not_found'> {
    return this.db.withTransaction(ownerUserId, async (tx) => {
      // The lock. A concurrent grantRole for this contact blocks here (or we
      // block on it), so exactly one of the two decides first and the other sees
      // the committed result.
      const locked = await tx.query<{ id: string }>(
        `SELECT id FROM contacts
          WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
          FOR UPDATE`,
        [id, ownerUserId],
      );
      if (locked.length === 0) {
        return 'not_found';
      }
      const live = await tx.query<{ id: string }>(
        `SELECT 1 AS id FROM role_assignments
          WHERE contact_id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
          LIMIT 1`,
        [id, ownerUserId],
      );
      if (live.length > 0) {
        return 'in_use';
      }
      await tx.query(`UPDATE contacts SET deleted_at = now() WHERE id = $1`, [id]);
      return 'deleted';
    });
  }

  async findById(id: string): Promise<ContactRow | null> {
    const rows = await this.db.query<ContactRow>(`${SELECT} WHERE id = $1 AND deleted_at IS NULL`, [
      id,
    ]);
    return rows[0] ?? null;
  }

  async listByOwner(ownerUserId: string): Promise<ContactRow[]> {
    return this.db.query<ContactRow>(
      `${SELECT} WHERE owner_user_id = $1 AND deleted_at IS NULL ORDER BY created_at`,
      [ownerUserId],
    );
  }
}

const SELECT = `SELECT id, owner_user_id, name_ct, email_ct, email_bidx, phone_ct, address_ct,
       relationship, professional_kind, linked_user_id, notes_ct, dek_id
  FROM contacts`;
