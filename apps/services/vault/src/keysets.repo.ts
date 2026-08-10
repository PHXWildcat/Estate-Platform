import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

export interface KeysetRow {
  user_id: string;
  srp_verifier: Buffer;
  srp_salt: Buffer;
  wrapped_master_key: Buffer;
  kdf_params: unknown;
  /** Raw P-256 point others seal emergency-access shares to. Public by nature. */
  public_key: Buffer | null;
  /** Wrapped under THIS user's master key, so only they can ever use it. */
  wrapped_private_key: Buffer | null;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = `user_id, srp_verifier, srp_salt, wrapped_master_key, kdf_params,
  public_key, wrapped_private_key, created_at, updated_at`;

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
   * Publish this user's emergency-access public key (and store their own
   * wrapped private half). Separate from the keyset replace path because it
   * changes no unlock material - it only makes the user addressable as someone
   * else's emergency contact.
   */
  async setRecoveryKeyPair(
    tx: Queryable,
    input: { userId: string; publicKey: Buffer; wrappedPrivateKey: Buffer },
  ): Promise<void> {
    await tx.query(
      `UPDATE vault_keysets SET public_key = $2, wrapped_private_key = $3 WHERE user_id = $1`,
      [input.userId, input.publicKey, input.wrappedPrivateKey],
    );
  }

  /**
   * Drop this user's emergency-access keypair.
   *
   * Called from reset: the private half is wrapped under the master key that
   * reset destroys, so leaving the public half published would invite other
   * owners to seal shares to a key whose private half is already unusable —
   * an escrow that looks healthy and silently fails at the one moment it has
   * to work. The DDL's all-or-nothing CHECK is what makes clearing both legal.
   */
  async clearRecoveryKeyPair(tx: Queryable, userId: string): Promise<void> {
    await tx.query(
      `UPDATE vault_keysets SET public_key = NULL, wrapped_private_key = NULL WHERE user_id = $1`,
      [userId],
    );
  }

  /**
   * The public key an owner will seal a share to. Returned to another user by
   * design - it is a public key - but the owner is expected to confirm its
   * fingerprint with the grantee out of band before trusting it (docs/03 §5.2
   * key substitution).
   */
  async findPublicKey(q: Queryable | Db, userId: string): Promise<Buffer | null> {
    const rows = await q.query<{ public_key: Buffer | null }>(
      `SELECT public_key FROM vault_keysets WHERE user_id = $1`,
      [userId],
    );
    return rows[0]?.public_key ?? null;
  }

  /**
   * The caller's OWN recovery keypair, public half and wrapped private half.
   *
   * M6 wrote `wrapped_private_key` and never served it back, so a grantee could
   * never open a share sealed to them — the release path was structurally
   * incompletable. Invisible until M15 PR3 became its first consumer, which is
   * the M4 legal-hold shape: a route with no caller hides the gap next to it.
   */
  async findRecoveryKeyPair(
    q: Queryable | Db,
    userId: string,
  ): Promise<{ publicKey: Buffer; wrappedPrivateKey: Buffer } | null> {
    const rows = await q.query<{ public_key: Buffer | null; wrapped_private_key: Buffer | null }>(
      `SELECT public_key, wrapped_private_key FROM vault_keysets WHERE user_id = $1`,
      [userId],
    );
    const row = rows[0];
    if (!row?.public_key || !row.wrapped_private_key) {
      return null;
    }
    return { publicKey: row.public_key, wrappedPrivateKey: row.wrapped_private_key };
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
