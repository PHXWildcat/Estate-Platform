import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

export interface KeysetRow {
  user_id: string;
  srp_verifier: Buffer;
  srp_salt: Buffer;
  wrapped_master_key: Buffer;
  kdf_params: unknown;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = `user_id, srp_verifier, srp_salt, wrapped_master_key, kdf_params, created_at, updated_at`;

/**
 * `vault_keysets` access. Everything in this table is opaque to the server: the
 * verifier proves nothing without the vault password AND the Secret Key, and
 * the wrapped master key cannot be unwrapped here at all.
 */
@Injectable()
export class KeysetsRepo {
  async findByUser(q: Queryable | Db, userId: string): Promise<KeysetRow | null> {
    const rows = await q.query<KeysetRow>(
      `SELECT ${COLUMNS} FROM vault_keysets WHERE user_id = $1`,
      [userId],
    );
    return rows[0] ?? null;
  }

  /** Row lock, so a keyset replacement cannot race a concurrent open. */
  async lockByUser(tx: Queryable, userId: string): Promise<KeysetRow | null> {
    const rows = await tx.query<KeysetRow>(
      `SELECT ${COLUMNS} FROM vault_keysets WHERE user_id = $1 FOR UPDATE`,
      [userId],
    );
    return rows[0] ?? null;
  }

  async insert(
    tx: Queryable,
    input: {
      userId: string;
      srpVerifier: Buffer;
      srpSalt: Buffer;
      wrappedMasterKey: Buffer;
      kdfParams: unknown;
    },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO vault_keysets (user_id, srp_verifier, srp_salt, wrapped_master_key, kdf_params)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        input.userId,
        input.srpVerifier,
        input.srpSalt,
        input.wrappedMasterKey,
        JSON.stringify(input.kdfParams),
      ],
    );
  }

  /**
   * Replace the keyset in place. The version-capture trigger records who
   * changed it and when, with the key material redacted - see the migration
   * for why retaining a superseded wrapped master key would be an attack asset
   * rather than an audit record.
   */
  async replace(
    tx: Queryable,
    input: {
      userId: string;
      srpVerifier: Buffer;
      srpSalt: Buffer;
      wrappedMasterKey: Buffer;
      kdfParams: unknown;
    },
  ): Promise<void> {
    await tx.query(
      `UPDATE vault_keysets
          SET srp_verifier = $2, srp_salt = $3, wrapped_master_key = $4, kdf_params = $5
        WHERE user_id = $1`,
      [
        input.userId,
        input.srpVerifier,
        input.srpSalt,
        input.wrappedMasterKey,
        JSON.stringify(input.kdfParams),
      ],
    );
  }
}
