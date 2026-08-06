import { Injectable } from '@nestjs/common';
import { Db } from './db';

/** A link invitation row, as the service needs to reason about it. */
export interface InvitationRow {
  id: string;
  owner_user_id: string;
  contact_id: string;
  expires_at: Date;
  attempts: number;
  redeemed_at: Date | null;
  revoked_at: Date | null;
}

/** How many wrong codes one invitation tolerates before it is spent. */
export const MAX_REDEEM_ATTEMPTS = 10;

/**
 * The contact became unlinkable between the service's check and the commit.
 * Rolls the redemption back so the invitation is NOT spent; the service turns
 * this into the same uniform refusal as every other failed redemption, because
 * telling a redeemer "someone else got there first" confirms the code was real.
 */
export class InvitationRaceError extends Error {
  constructor() {
    super('contact became unlinkable during redemption');
    this.name = 'InvitationRaceError';
  }
}

/**
 * The only writer of `contacts.linked_user_id` in the platform.
 *
 * Every statement here is scoped so that the CODE is the sole selector on the
 * redemption path and the OWNER is the sole selector on every other path. That
 * split is the anti-enumeration property docs/03 §6b depends on: a redeemer
 * cannot name an estate, and an owner cannot name a user.
 */
@Injectable()
export class ContactLinksRepo {
  constructor(private readonly db: Db) {}

  /**
   * Revoke any live invitation for a contact and insert a new one, in ONE
   * statement pair inside the caller's transaction-less path.
   *
   * Re-issuing rather than refusing is deliberate: an owner who lost the code
   * they were told once must not be stuck, and the partial unique index would
   * otherwise make the obvious remedy an error. The revoke is audited too, so
   * the trail still shows a code was retired.
   */
  async revokeLive(ownerUserId: string, contactId: string): Promise<string | null> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE contact_link_invitations SET revoked_at = now()
        WHERE owner_user_id = $1 AND contact_id = $2
          AND redeemed_at IS NULL AND revoked_at IS NULL
        RETURNING id`,
      [ownerUserId, contactId],
    );
    return rows[0]?.id ?? null;
  }

  async insert(input: {
    ownerUserId: string;
    contactId: string;
    codeSha256: Buffer;
    expiresAt: Date;
  }): Promise<string> {
    const rows = await this.db.query<{ id: string }>(
      `INSERT INTO contact_link_invitations (owner_user_id, contact_id, code_sha256, expires_at)
       VALUES ($1,$2,$3,$4)
       RETURNING id`,
      [input.ownerUserId, input.contactId, input.codeSha256, input.expiresAt],
    );
    return (rows[0] as { id: string }).id;
  }

  /**
   * Find an invitation BY CODE HASH ALONE — the redemption path's only lookup.
   *
   * Deliberately returns the row whatever its state (expired, spent, revoked)
   * so the service can count an attempt against a real code, and deliberately
   * takes no user id: the redeemer has no relationship to the estate yet, so
   * there is nothing to scope by.
   */
  async findByCode(codeSha256: Buffer): Promise<InvitationRow | null> {
    const rows = await this.db.query<InvitationRow>(
      `SELECT id, owner_user_id, contact_id, expires_at, attempts, redeemed_at, revoked_at
         FROM contact_link_invitations
        WHERE code_sha256 = $1`,
      [codeSha256],
    );
    return rows[0] ?? null;
  }

  /** Count a failed redemption against a real invitation. */
  async countAttempt(id: string): Promise<void> {
    await this.db.query(
      `UPDATE contact_link_invitations SET attempts = attempts + 1 WHERE id = $1`,
      [id],
    );
  }

  /**
   * Spend the invitation AND write the link — BOTH OR NEITHER.
   *
   * Inside one transaction, because the halves must not come apart: an
   * invitation marked spent with no link written locks that contact out of ever
   * being linked, and a link written from an invitation still live is
   * replayable. Each statement also RESTATES its own preconditions in its
   * `WHERE` rather than trusting the service's earlier read — two concurrent
   * redemptions of the same code therefore produce exactly one link, and the
   * loser rolls back rather than overwriting. That is the CAS shape M7's
   * owner-liveness interlock uses, for the same reason: a read and a commit
   * separated by anything at all is a race unless the commit re-checks.
   *
   * The version-capture trigger on `contacts` records the REDEEMER as the actor,
   * which is what the trail should say about who caused the link.
   */
  async redeem(input: {
    invitationId: string;
    contactId: string;
    redeemedBy: string;
    now: Date;
  }): Promise<boolean> {
    return this.db.withTransaction(input.redeemedBy, async (tx) => {
      const spent = await tx.query<{ id: string }>(
        `UPDATE contact_link_invitations
            SET redeemed_at = $2, redeemed_by = $3
          WHERE id = $1
            AND redeemed_at IS NULL
            AND revoked_at IS NULL
            AND expires_at > $2
          RETURNING id`,
        [input.invitationId, input.now, input.redeemedBy],
      );
      if (spent.length === 0) {
        return false;
      }
      const linked = await tx.query<{ id: string }>(
        `UPDATE contacts SET linked_user_id = $2
          WHERE id = $1
            AND linked_user_id IS NULL
            AND deleted_at IS NULL
          RETURNING id`,
        [input.contactId, input.redeemedBy],
      );
      if (linked.length === 0) {
        // The contact was linked or deleted between the read and here. Undo the
        // spend by failing the whole transaction — a spent invitation for a
        // contact that never got linked is a dead end nobody can clear.
        throw new InvitationRaceError();
      }
      return true;
    });
  }

  /**
   * Remove a link. The owner's own act, and the one that must stay easy — see
   * the controller for why it is not step-up gated.
   */
  async unlink(ownerUserId: string, contactId: string): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE contacts SET linked_user_id = NULL
        WHERE id = $1 AND owner_user_id = $2
          AND linked_user_id IS NOT NULL AND deleted_at IS NULL
        RETURNING id`,
      [contactId, ownerUserId],
    );
    return rows.length > 0;
  }
}
