import { Injectable } from '@nestjs/common';
import { Db } from './db';

/**
 * One estate that names the caller (M22 PR4a). The owner's NAME is not here —
 * this repo returns ciphertext and the key to read it, and the decrypt happens
 * in the service where it can be audited as the cross-user disclosure it is.
 */
export interface LinkedEstateRow {
  owner_user_id: string;
  contact_id: string;
  roles: string[];
  /** NULL when the owner has never saved a profile — a real answer, not an error. */
  legal_name_ct: Buffer | null;
  dek_id: string | null;
}

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
   * THE REVERSE OF EVERY OTHER READ IN THIS SERVICE (M22 PR4a).
   *
   * Everything else here is owner→contact: an owner listing the people they
   * named. This is contact→owner — "whose estates name ME" — and until this
   * query the platform could not answer it at all. `redeemContactLink` returns
   * `Ok!` and tells the redeemer nothing, so somebody who accepted an
   * invitation months ago had no way to learn what they had accepted, and
   * settlement's reportable-estates list is a set of bare UUIDs for the same
   * reason.
   *
   * The JOIN to `profiles` is a CROSS-USER read: the row belongs to the owner,
   * not to the caller. It returns CIPHERTEXT and the dek id — never plaintext —
   * so the decision to decrypt, and the audit event that must precede it, live
   * in the service. A LEFT JOIN because a profile may not exist: an owner who
   * never saved one has no name to disclose, and that is a real answer.
   *
   * `deleted_at IS NULL` on the contact is the authorization edge itself. An
   * owner who unlinks (one click, no step-up — the protective action is never
   * the harder one) removes the row and this read stops answering, which is
   * what makes the disclosure revocable rather than permanent.
   */
  async listEstatesNaming(userId: string): Promise<LinkedEstateRow[]> {
    return this.db.query<LinkedEstateRow>(
      `SELECT c.owner_user_id,
              c.id AS contact_id,
              array_remove(array_agg(DISTINCT ra.role), NULL) AS roles,
              p.legal_name_ct,
              p.dek_id
         FROM contacts c
         LEFT JOIN role_assignments ra
           ON ra.contact_id = c.id AND ra.deleted_at IS NULL
         LEFT JOIN profiles p
           ON p.user_id = c.owner_user_id
        WHERE c.linked_user_id = $1
          AND c.deleted_at IS NULL
        GROUP BY c.owner_user_id, c.id, p.legal_name_ct, p.dek_id
        ORDER BY c.owner_user_id`,
      [userId],
    );
  }

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
   * replayable. Each statement also RESTATES THE PRECONDITIONS THAT DECIDE
   * WHETHER THE LINK MAY EXIST — live, unrevoked, unexpired, contact unlinked
   * and undeleted — rather than trusting the service's earlier read, so two
   * concurrent redemptions of the same code produce exactly one link and the
   * loser rolls back. That is the CAS shape M7's owner-liveness interlock uses,
   * for the same reason: a read and a commit separated by anything at all is a
   * race unless the commit re-checks.
   *
   * The ATTEMPT CAP is deliberately not restated here, and the asymmetry is the
   * point: the cap bounds presentations of a wrong code, and this statement only
   * ever runs for the RIGHT one. Racing it could at most let a correct code
   * succeed on the same tick its counter crossed the threshold — which is the
   * outcome the holder of a correct code is entitled to anyway.
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
