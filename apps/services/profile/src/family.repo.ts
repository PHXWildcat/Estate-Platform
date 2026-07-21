import { Injectable } from '@nestjs/common';
import { Db } from './db';

export interface FamilyMemberRow {
  id: string;
  user_id: string;
  relation: string;
  name_ct: Buffer;
  dob_ct: Buffer | null;
  is_minor: boolean | null;
  notes_ct: Buffer | null;
  dek_id: string;
}

export type FamilyMemberInsert = Omit<FamilyMemberRow, 'id'>;

@Injectable()
export class FamilyRepo {
  constructor(private readonly db: Db) {}

  async insert(row: FamilyMemberInsert): Promise<string> {
    const rows = await this.db.query<{ id: string }>(
      `INSERT INTO family_members (user_id, relation, name_ct, dob_ct, is_minor, notes_ct, dek_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id`,
      [row.user_id, row.relation, row.name_ct, row.dob_ct, row.is_minor, row.notes_ct, row.dek_id],
    );
    return (rows[0] as { id: string }).id;
  }

  /** Update only rows owned by `userId` (ownership enforced in the WHERE). */
  async update(id: string, userId: string, row: FamilyMemberInsert): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE family_members
          SET relation = $3, name_ct = $4, dob_ct = $5, is_minor = $6, notes_ct = $7, dek_id = $8
        WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
        RETURNING id`,
      [id, userId, row.relation, row.name_ct, row.dob_ct, row.is_minor, row.notes_ct, row.dek_id],
    );
    return rows.length > 0;
  }

  async softDelete(id: string, userId: string): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE family_members SET deleted_at = now()
        WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
        RETURNING id`,
      [id, userId],
    );
    return rows.length > 0;
  }

  async listByOwner(userId: string): Promise<FamilyMemberRow[]> {
    return this.db.query<FamilyMemberRow>(
      `SELECT id, user_id, relation, name_ct, dob_ct, is_minor, notes_ct, dek_id
         FROM family_members
        WHERE user_id = $1 AND deleted_at IS NULL
        ORDER BY created_at`,
      [userId],
    );
  }
}
