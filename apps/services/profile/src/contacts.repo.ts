import { Injectable } from '@nestjs/common';
import { Db } from './db';

export interface ContactRow {
  id: string;
  owner_user_id: string;
  name_ct: Buffer;
  email_ct: Buffer | null;
  email_bidx: Buffer | null;
  phone_ct: Buffer | null;
  address_ct: Buffer | null;
  relationship: string | null;
  professional_kind: string | null;
  linked_user_id: string | null;
  notes_ct: Buffer | null;
  dek_id: string;
}

export type ContactInsert = Omit<ContactRow, 'id'>;

@Injectable()
export class ContactsRepo {
  constructor(private readonly db: Db) {}

  async insert(row: ContactInsert): Promise<string> {
    const rows = await this.db.query<{ id: string }>(
      `INSERT INTO contacts (
         owner_user_id, name_ct, email_ct, email_bidx, phone_ct, address_ct,
         relationship, professional_kind, linked_user_id, notes_ct, dek_id
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
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
        row.linked_user_id,
        row.notes_ct,
        row.dek_id,
      ],
    );
    return (rows[0] as { id: string }).id;
  }

  async update(id: string, ownerUserId: string, row: ContactInsert): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE contacts SET
         name_ct = $3, email_ct = $4, email_bidx = $5, phone_ct = $6, address_ct = $7,
         relationship = $8, professional_kind = $9, linked_user_id = $10, notes_ct = $11, dek_id = $12
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
        row.linked_user_id,
        row.notes_ct,
        row.dek_id,
      ],
    );
    return rows.length > 0;
  }

  async softDelete(id: string, ownerUserId: string): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE contacts SET deleted_at = now()
        WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
        RETURNING id`,
      [id, ownerUserId],
    );
    return rows.length > 0;
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
