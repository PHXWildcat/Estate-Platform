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
   * Soft-delete, REFUSING IN THE SAME STATEMENT if a live role assignment names
   * this contact.
   *
   * The predicate is here rather than only in the service because the service's
   * version was check-then-act: a `grantRole` committing between the check and
   * this UPDATE would delete a contact that had just acquired a designation,
   * recreating the exact fail-open docs/03 §6f declares Closed — the executor
   * stops resolving, every grant stops being effective, the assignment is still
   * listed, and no `role.revoked` is emitted. Restating the precondition in the
   * WHERE makes the two atomic against each other, which is the same CAS
   * discipline the link redemption and M7's owner-liveness interlock use.
   *
   * Returning a discriminated outcome rather than a boolean keeps "nothing to
   * delete" (404) apart from "a designation stands in the way" (409): they are
   * different facts with different remedies.
   */
  async softDelete(id: string, ownerUserId: string): Promise<'deleted' | 'in_use' | 'not_found'> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE contacts SET deleted_at = now()
        WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM role_assignments ra
             WHERE ra.contact_id = contacts.id
               AND ra.owner_user_id = $2
               AND ra.deleted_at IS NULL
          )
        RETURNING id`,
      [id, ownerUserId],
    );
    if (rows.length > 0) {
      return 'deleted';
    }
    // Nothing changed: distinguish the two reasons for the caller's error code.
    const live = await this.db.query<{ in_use: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM role_assignments ra
          WHERE ra.contact_id = $1 AND ra.owner_user_id = $2 AND ra.deleted_at IS NULL
       ) AS in_use
        FROM contacts c
       WHERE c.id = $1 AND c.owner_user_id = $2 AND c.deleted_at IS NULL`,
      [id, ownerUserId],
    );
    if (live.length === 0) {
      return 'not_found';
    }
    return live[0]?.in_use === true ? 'in_use' : 'not_found';
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
