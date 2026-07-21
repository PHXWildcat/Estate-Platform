import { Injectable } from '@nestjs/common';
import { Db } from './db';

/** Ciphertext + metadata for a profile row. All *_ct columns are AEAD BYTEA. */
export interface ProfileRow {
  user_id: string;
  legal_name_ct: Buffer;
  dob_ct: Buffer | null;
  ssn_ct: Buffer | null;
  ssn_last4_ct: Buffer | null;
  address_ct: Buffer | null;
  phone_ct: Buffer | null;
  occupation_ct: Buffer | null;
  marital_status: string | null;
  state_of_residence: string | null;
  dek_id: string;
}

@Injectable()
export class ProfileRepo {
  constructor(private readonly db: Db) {}

  /** Upsert the caller's 1:1 profile (INSERT ... ON CONFLICT (user_id)). */
  async upsert(row: ProfileRow): Promise<void> {
    await this.db.query(
      `INSERT INTO profiles (
         user_id, legal_name_ct, dob_ct, ssn_ct, ssn_last4_ct, address_ct,
         phone_ct, occupation_ct, marital_status, state_of_residence, dek_id
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (user_id) DO UPDATE SET
         legal_name_ct = EXCLUDED.legal_name_ct,
         dob_ct = EXCLUDED.dob_ct,
         ssn_ct = EXCLUDED.ssn_ct,
         ssn_last4_ct = EXCLUDED.ssn_last4_ct,
         address_ct = EXCLUDED.address_ct,
         phone_ct = EXCLUDED.phone_ct,
         occupation_ct = EXCLUDED.occupation_ct,
         marital_status = EXCLUDED.marital_status,
         state_of_residence = EXCLUDED.state_of_residence,
         dek_id = EXCLUDED.dek_id`,
      [
        row.user_id,
        row.legal_name_ct,
        row.dob_ct,
        row.ssn_ct,
        row.ssn_last4_ct,
        row.address_ct,
        row.phone_ct,
        row.occupation_ct,
        row.marital_status,
        row.state_of_residence,
        row.dek_id,
      ],
    );
  }

  async findByUserId(userId: string): Promise<ProfileRow | null> {
    const rows = await this.db.query<ProfileRow>(
      `SELECT user_id, legal_name_ct, dob_ct, ssn_ct, ssn_last4_ct, address_ct,
              phone_ct, occupation_ct, marital_status, state_of_residence, dek_id
         FROM profiles
        WHERE user_id = $1 AND deleted_at IS NULL`,
      [userId],
    );
    return rows[0] ?? null;
  }
}
