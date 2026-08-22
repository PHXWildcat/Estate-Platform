import { Injectable } from '@nestjs/common';
import { Db, isUniqueViolation, type Queryable } from './db';

export interface UserRow {
  id: string;
  password_hash: string | null;
  status: string;
  dek_id: string;
  /** The login selector — returned so the change ceremony can refuse a no-op
   * "change to my current address" without a second read (M17 PR4). */
  email_bidx: Buffer;
}

@Injectable()
export class UsersRepo {
  constructor(private readonly db: Db) {}

  /**
   * Insert a new user. Returns 'duplicate' (instead of throwing) when the
   * email blind index collides with a live row — the register endpoint must
   * behave identically for new and existing emails (no account enumeration).
   */
  async insert(input: {
    id: string;
    emailCt: Buffer;
    emailBidx: Buffer;
    passwordHash: string;
    dekId: string;
  }): Promise<'inserted' | 'duplicate'> {
    try {
      await this.db.query(
        `INSERT INTO users (id, email_ct, email_bidx, password_hash, dek_id)
         VALUES ($1, $2, $3, $4, $5)`,
        [input.id, input.emailCt, input.emailBidx, input.passwordHash, input.dekId],
      );
      return 'inserted';
    } catch (err) {
      if (isUniqueViolation(err)) {
        return 'duplicate';
      }
      throw err;
    }
  }

  async findByEmailBidx(emailBidx: Buffer): Promise<UserRow | null> {
    const rows = await this.db.query<UserRow>(
      `SELECT id, password_hash, status, dek_id
         FROM users
        WHERE email_bidx = $1 AND deleted_at IS NULL`,
      [emailBidx],
    );
    return rows[0] ?? null;
  }

  async findById(userId: string): Promise<UserRow | null> {
    const rows = await this.db.query<UserRow>(
      `SELECT id, password_hash, status, dek_id, email_bidx
         FROM users
        WHERE id = $1 AND deleted_at IS NULL`,
      [userId],
    );
    return rows[0] ?? null;
  }

  /**
   * Replace the password hash (M17 PR2) — the FIRST write this column has ever
   * had. It was set once at INSERT and read twice at login, and nothing else.
   *
   * TAKES A `Queryable`, so the caller can pass an open transaction. That is
   * not a convenience: the hash write and the session revocation have to commit
   * together or a crash between them leaves either every old credential live
   * under a new password, or a user signed out of an account whose password did
   * not change.
   *
   * THE STATUS ALLOWLIST RIDES THE UPDATE rather than being checked above it —
   * the M13 `contact_in_use` lesson. It is the same set the session lookups
   * use: `deceased_pending` is permitted because docs/03 §5.1's rescue path is
   * the living owner signing in and voiding the case, and being unable to
   * change a password would make that harder for exactly the person the case
   * targets; `settlement` and every other status are refused, because reopening
   * a terminally locked account is what that status exists to prevent.
   *
   * Returns whether a row matched, so the caller can answer without a second
   * read that could race.
   */
  async updatePasswordHash(tx: Queryable, userId: string, passwordHash: string): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE users
          SET password_hash = $2, updated_at = now()
        WHERE id = $1
          AND deleted_at IS NULL
          AND status IN ('active', 'deceased_pending')
        RETURNING id`,
      [userId, passwordHash],
    );
    return rows.length > 0;
  }

  /**
   * THE SWITCH (M17 PR4): move a proven candidate address onto the live row.
   *
   * The ciphertext arrives from `email_changes` byte-for-byte — it was
   * encrypted as `users.email` under the user's live DEK at staging, so no
   * decrypt happens on this side of the transaction. The status allowlist is
   * `updatePasswordHash`'s, for its reasons. `dek_id` is restated HERE, in the
   * same statement as the write: if the account's key changed between mint and
   * redemption, this ciphertext no longer belongs on the row (the M4 rule that
   * a shredded record is Gone, never silently re-keyed), and a check anywhere
   * earlier would be check-then-act.
   *
   * A unique violation on `ux_users_email` (the candidate address was
   * registered by someone else during the ceremony window) is the CALLER's to
   * map — this repo lets it throw so the transaction rolls back whole.
   */
  async updateEmail(
    tx: Queryable,
    userId: string,
    input: { emailCt: Buffer; emailBidx: Buffer; dekId: string },
  ): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE users
          SET email_ct = $2, email_bidx = $3, updated_at = now()
        WHERE id = $1
          AND deleted_at IS NULL
          AND status IN ('active', 'deceased_pending')
          AND dek_id = $4
        RETURNING id`,
      [userId, input.emailCt, input.emailBidx, input.dekId],
    );
    return rows.length > 0;
  }

  /**
   * ERASURE, THE PART THAT IS NOT THE KEY (M25 PR3). Closes the account and
   * replaces the live blind index in ONE statement.
   *
   * WHY THE BLIND INDEX HAS TO BE OVERWRITTEN AT ALL. `email_bidx` is an HMAC
   * under a service-wide key (`EMAIL_INDEX_KEY_HEX`), which puts it OUTSIDE the
   * per-user envelope — so destroying the DEK erases `email_ct` and leaves the
   * index that finds the row by address perfectly intact. An erased account
   * still answerable to "is this address registered" is erased in the way that
   * matters least. This is docs/03 §6kk's `[OWNER: M25]` residual, and it is
   * the reason PR1 had to land first: `CREATE OR REPLACE FUNCTION` only affects
   * FUTURE captures, so had this UPDATE run under the old capture body it would
   * have copied the old `email_bidx` into `users_versions`, where REVOKE
   * UPDATE, DELETE means no later migration could retract it. Erasure would
   * have immortalised the very value it was erasing.
   *
   * THE REPLACEMENT IS RANDOM, NOT NULL OR A CONSTANT. `ux_users_email` is
   * unique, so a constant would let the second erasure collide with the first
   * and fail — and NULL would make every erased account match every other on an
   * IS NULL scan. Random bytes of the same width are unlinkable to the address,
   * unlinkable to each other, and indistinguishable in shape from a live row.
   *
   * `email_ct` IS DELIBERATELY LEFT ALONE, here and in the version shadow. It
   * is ciphertext under the DEK this erasure destroys, and crypto-shredding
   * reaching every copy — including the append-only ones — is the whole reason
   * this repo deletes keys instead of rows.
   *
   * `password_hash` IS CLEARED, and migration 008 is the argument (M25 PR5).
   * That migration redacted the verifier from the version shadow in M17 and
   * said why in a sentence written eight milestones before erasure existed:
   * `password_hash` "sits outside the envelope and erasure does not reach it.
   * A row image that survives crypto-shredding must not contain a credential
   * verifier." The reasoning was right and it was applied to ONE member of the
   * category — the captured image — while the LIVE column was left to a
   * milestone that had not been written yet. This is that milestone. An
   * Argon2id verifier is not the password, but it is derived from a secret its
   * owner may well have used elsewhere, and an erased account keeping one
   * forever is the one thing left in this row that a database dump could still
   * be worked on offline.
   *
   * SAFE BECAUSE THE COLUMN IS ALREADY NULLABLE — 001 declares it "NULL if
   * passkey-only", so passkey-only accounts have lived with a null hash since
   * M1 and every reader already guards it: `login` and `changePassword` both
   * refuse on `password_hash === null` before reaching the verifier, and
   * `updatePasswordHash`'s own allowlist excludes 'closed' anyway.
   *
   * The `from` allowlist travels in the statement, as `updateStatusFrom`'s
   * does: the claim that made this account eligible was made before the grace
   * period, and a status that moved since must stop the write here rather than
   * be trusted from a read above it.
   */
  async closeAndUnlinkEmail(
    tx: Queryable,
    userId: string,
    from: readonly string[],
    emailBidx: Buffer,
  ): Promise<{ id: string; dek_id: string } | null> {
    const rows = await tx.query<{ id: string; dek_id: string }>(
      `UPDATE users
          SET status = 'closed',
              email_bidx = $3,
              password_hash = NULL,
              updated_at = now()
        WHERE id = $1 AND deleted_at IS NULL AND status = ANY($2)
       RETURNING id, dek_id`,
      [userId, [...from], emailBidx],
    );
    return rows[0] ?? null;
  }

  /**
   * Compare-and-set status transition (M7 settlement lock). The allowed `from`
   * set travels in the SQL so a concurrent transition cannot be overwritten:
   * zero rows updated means the row was missing OR its status had already
   * moved — the caller re-reads to tell the two apart.
   *
   * `notAfterStepUp` is the owner-liveness interlock (docs/03 §5.1: "any owner
   * sign-in with step-up MFA instantly voids the case"). Settlement re-reads
   * liveness before asking for the terminal `settlement` transition, but that
   * read and this write are separated by a network hop — so the predicate is
   * restated HERE, in the same single statement as the write, against the
   * append-only ledger that lives in this cluster. A step-up granted after
   * the watermark makes the UPDATE match zero rows: a living owner cannot be
   * locked out by a step-up that landed while the transition was in flight.
   */
  async updateStatusFrom(
    userId: string,
    from: readonly string[],
    to: string,
    notAfterStepUp?: Date,
  ): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE users
          SET status = $3
        WHERE id = $1 AND deleted_at IS NULL AND status = ANY($2)
          AND ($4::timestamptz IS NULL OR NOT EXISTS (
                SELECT 1 FROM auth_events
                 WHERE user_id = $1
                   AND kind = 'stepup.granted'
                   AND occurred_at > $4
              ))
        RETURNING id`,
      [userId, [...from], to, notAfterStepUp ?? null],
    );
    return rows.length > 0;
  }
}
