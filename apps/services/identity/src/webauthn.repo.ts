import { Injectable } from '@nestjs/common';
import { Db } from './db';

/** A stored passkey. `sign_count` is BIGINT, so pg returns it as a string. */
export interface WebAuthnCredentialRow {
  id: string;
  user_id: string;
  credential_id: Buffer;
  public_key: Buffer;
  sign_count: string;
  transports: string[] | null;
  aaguid: string | null;
  nickname: string | null;
  is_hardware_key: boolean;
}

export type WebAuthnChallengeKind = 'registration' | 'authentication';

/**
 * Repository for the WebAuthn tables (docs/02 §1 `webauthn_credentials`, plus
 * the additive single-use `webauthn_challenges` store). Raw parameterized pg
 * through the shared `Db` provider — same pattern as the other repos.
 */
@Injectable()
export class WebAuthnRepo {
  constructor(private readonly db: Db) {}

  async insertCredential(input: {
    userId: string;
    credentialId: Buffer;
    publicKey: Buffer;
    signCount: number;
    transports: string[] | null;
    aaguid: string | null;
    nickname: string | null;
    isHardwareKey: boolean;
  }): Promise<'inserted' | 'duplicate'> {
    try {
      await this.#insert(input);
      return 'inserted';
    } catch (err) {
      // `credential_id` is globally UNIQUE — the same authenticator registered
      // from a SECOND account lands here (excludeCredentials only covers the
      // caller's own). A typed outcome rather than an unhandled 500: the
      // service folds it into the one generic ceremony refusal, because
      // "this authenticator belongs to another account" is a fact about
      // somebody else's account (M17 PR5; found by the fact sweep before the
      // route had its first real caller).
      if (typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505') {
        return 'duplicate';
      }
      throw err;
    }
  }

  async #insert(input: {
    userId: string;
    credentialId: Buffer;
    publicKey: Buffer;
    signCount: number;
    transports: string[] | null;
    aaguid: string | null;
    nickname: string | null;
    isHardwareKey: boolean;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO webauthn_credentials
         (user_id, credential_id, public_key, sign_count, transports, aaguid, nickname, is_hardware_key)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        input.userId,
        input.credentialId,
        input.publicKey,
        input.signCount,
        input.transports,
        input.aaguid,
        input.nickname,
        input.isHardwareKey,
      ],
    );
  }

  /** All active (non-revoked) credentials for a user. */
  /**
   * Does this account hold ANY passkey?
   *
   * The WebAuthn half of `SecondFactorGate.holdsVerifiedFactor`. A boolean
   * rather than a row list, deliberately: the caller needs the fact, and
   * returning credentials would put key material on a path that has no business
   * holding it. There is no `verified_at` here because a WebAuthn credential is
   * only ever inserted AFTER a verified ceremony — registration is the
   * verification, unlike TOTP where enrolment and confirmation are two steps.
   */
  async hasCredentials(userId: string): Promise<boolean> {
    // `revoked_at IS NULL`, exactly like every other read here — added by M17
    // PR5 in the same change as the FIRST writer of `revoked_at`. Without it,
    // revoking the last passkey on a TOTP-less account would leave
    // `holdsVerifiedFactor` true forever: `SecondFactorGate` would demand a
    // fresh factor the user can no longer produce, permanently locking factor
    // enrolment AND every arming gate. Latent before PR5 only because nothing
    // ever wrote the column; the fence rule applies — the predicate lands with
    // the writer, never after it.
    const rows = await this.db.query<{ present: boolean }>(
      `SELECT true AS present
         FROM webauthn_credentials
        WHERE user_id = $1 AND revoked_at IS NULL
        LIMIT 1`,
      [userId],
    );
    return rows.length > 0;
  }

  async findCredentialsByUser(userId: string): Promise<WebAuthnCredentialRow[]> {
    return this.db.query<WebAuthnCredentialRow>(
      `SELECT id, user_id, credential_id, public_key, sign_count, transports,
              aaguid, nickname, is_hardware_key
         FROM webauthn_credentials
        WHERE user_id = $1 AND revoked_at IS NULL
        ORDER BY created_at ASC`,
      [userId],
    );
  }

  /** Active credential by its raw credential id (unique). */
  async findCredentialById(credentialId: Buffer): Promise<WebAuthnCredentialRow | null> {
    const rows = await this.db.query<WebAuthnCredentialRow>(
      `SELECT id, user_id, credential_id, public_key, sign_count, transports,
              aaguid, nickname, is_hardware_key
         FROM webauthn_credentials
        WHERE credential_id = $1 AND revoked_at IS NULL`,
      [credentialId],
    );
    return rows[0] ?? null;
  }

  /** Persist the post-authentication signature counter and touch last_used_at. */
  async updateSignCount(credentialId: Buffer, signCount: number, lastUsedAt: Date): Promise<void> {
    await this.db.query(
      `UPDATE webauthn_credentials
          SET sign_count = $2, last_used_at = $3
        WHERE credential_id = $1`,
      [credentialId, signCount, lastUsedAt],
    );
  }

  /**
   * The management projection (M17 PR5): what the security page shows. Row id,
   * label and timestamps ONLY — never `credential_id`, `public_key` or
   * `sign_count`, which no client needs and which would put key-adjacent
   * material on a listing path (the M16 session-list rule: return nothing the
   * data cannot keep a promise about).
   */
  async listForUser(userId: string): Promise<
    Array<{
      id: string;
      nickname: string | null;
      is_hardware_key: boolean;
      created_at: Date;
      last_used_at: Date | null;
    }>
  > {
    return this.db.query(
      `SELECT id, nickname, is_hardware_key, created_at, last_used_at
         FROM webauthn_credentials
        WHERE user_id = $1 AND revoked_at IS NULL
        ORDER BY created_at ASC`,
      [userId],
    );
  }

  /**
   * Revoke one credential — the FIRST writer `revoked_at` has ever had.
   *
   * The owner predicate rides the UPDATE (the M16 `revokeOwned` shape): the id
   * arrives in a URL, so a statement without it would let any authenticated
   * caller kill any passkey in the product. The boolean return is what lets
   * the route answer a UNIFORM 404 for "no such credential" and "not yours"
   * alike.
   */
  async revokeCredential(userId: string, id: string, now: Date): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE webauthn_credentials
          SET revoked_at = $3
        WHERE id = $1
          AND user_id = $2
          AND revoked_at IS NULL
      RETURNING id`,
      [id, userId, now],
    );
    return rows.length > 0;
  }

  /**
   * Name one credential — the first writer `nickname` has ever had. A plain
   * display label (the `documents.title` class: low-sensitivity metadata),
   * owner-predicated like the revoke.
   */
  async renameCredential(userId: string, id: string, nickname: string): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE webauthn_credentials
          SET nickname = $3
        WHERE id = $1
          AND user_id = $2
          AND revoked_at IS NULL
      RETURNING id`,
      [id, userId, nickname],
    );
    return rows.length > 0;
  }

  async insertChallenge(input: {
    userId: string | null;
    challenge: string;
    kind: WebAuthnChallengeKind;
    expiresAt: Date;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO webauthn_challenges (user_id, challenge, kind, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [input.userId, input.challenge, input.kind, input.expiresAt],
    );
  }

  /**
   * Find-and-delete the most recent challenge for (user, kind): the delete is
   * the point — a challenge is single-use, so it is consumed whether or not it
   * had expired. Returns the challenge string only when it was still fresh;
   * an expired (but now deleted) challenge returns null.
   */
  async consumeChallenge(
    userId: string,
    kind: WebAuthnChallengeKind,
    now: Date,
  ): Promise<string | null> {
    const rows = await this.db.query<{ challenge: string; expires_at: Date }>(
      `DELETE FROM webauthn_challenges
        WHERE id IN (
          SELECT id FROM webauthn_challenges
           WHERE user_id = $1 AND kind = $2
           ORDER BY created_at DESC
           LIMIT 1
        )
      RETURNING challenge, expires_at`,
      [userId, kind],
    );
    const row = rows[0];
    if (!row || row.expires_at.getTime() <= now.getTime()) {
      return null;
    }
    return row.challenge;
  }
}
