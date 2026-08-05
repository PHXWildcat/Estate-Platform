import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

export interface ConversationRow {
  id: string;
  user_id: string;
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
}

const COLUMNS = 'id, user_id, created_at, updated_at, deleted_at';

/**
 * `assistant_conversations` — the one mutable business table in this service.
 *
 * OWNERSHIP IS A WHERE CLAUSE FOR THE LIST PATH, AND A CEDAR DECISION FOR
 * EVERYTHING ELSE. `listLiveByUser` scopes by `user_id` because a listing has
 * no single resource to decide about — the predicate IS the answer. Every
 * single-conversation path instead resolves the row BY ID ALONE
 * (`getLiveById` / `lockLiveById`) and hands it to `AssistantAuthz`, which asks
 * assistant.cedar whether this principal may take this action on this
 * conversation.
 *
 * That is deliberate, and it is not the cheaper option. An owner predicate
 * makes the authorization rule an invisible property of six SQL strings, where
 * a reviewer has to read every one of them and notice the `$2` to know what the
 * rule is — and where a rule that is merely omitted looks exactly like a query.
 * A policy states it once, in a file a reviewer can read end to end, and it
 * states the NEGATIVE too: assistant.cedar carries no trustee permit, no
 * executor permit, no beneficiary permit and no operator permit, and their
 * absence is the security claim (a transcript quotes whatever estate content
 * the assistant retrieved, so a role-holder who may read one asset must not
 * thereby read a conversation that discusses every asset). A WHERE clause
 * cannot express "and nobody else, ever"; deny-by-default over an explicit
 * permit list does, and it fails a policy test if a later milestone widens it.
 *
 * A conversation belonging to someone else and a conversation that does not
 * exist still produce the SAME answer to the caller — one throws from the
 * policy decision, the other from a null row, and both land on the service's
 * uniform 404 (the documents/settlement convention). Anything else would be an
 * oracle confirming that a stranger's conversation id is real.
 *
 * `softDelete` keeps its owner predicate anyway. It is not the access decision
 * any more — the service has already asked Cedar by the time it runs — but a
 * destructive write that can only ever touch the row it was told about is worth
 * having at the data layer for free.
 */
@Injectable()
export class ConversationsRepo {
  /**
   * Open a conversation. INSERT fires no version trigger (the trigger is BEFORE
   * UPDATE OR DELETE), so this needs no transaction of its own — an
   * unreferenced empty row is the entire blast radius of a failure here.
   */
  async create(q: Queryable | Db, id: string, userId: string): Promise<ConversationRow> {
    const rows = await q.query<ConversationRow>(
      `INSERT INTO assistant_conversations (id, user_id) VALUES ($1, $2) RETURNING ${COLUMNS}`,
      [id, userId],
    );
    const row = rows[0];
    if (row === undefined) {
      // RETURNING on a successful INSERT always yields a row; this guards the
      // type, not a reachable state.
      throw new Error('assistant_conversations insert returned no row');
    }
    return row;
  }

  /**
   * One live conversation, resolved BY ID ALONE, or null if no live row has
   * that id.
   *
   * `user_id` comes back with it because the caller needs it: it is the
   * `subject` attribute of the Cedar resource, so the row is what the policy
   * decides ABOUT rather than something the query has already decided. Passing
   * the owner in here instead would make the subsequent `assertCan` a check
   * that cannot fail — decoration rather than a control.
   */
  async getLiveById(q: Queryable | Db, id: string): Promise<ConversationRow | null> {
    const rows = await q.query<ConversationRow>(
      `SELECT ${COLUMNS} FROM assistant_conversations
        WHERE id = $1 AND deleted_at IS NULL`,
      [id],
    );
    return rows[0] ?? null;
  }

  /**
   * The same read, holding the row for the rest of the caller's transaction.
   *
   * A turn appends at `max(seq) + 1`, so two turns racing on one conversation
   * would compute the same next seq; the UNIQUE index on
   * (conversation_id, seq) refuses the loser, but only after a provider call
   * has already been paid for and — worse — after its tool reads have already
   * run. Taking the row lock FIRST serializes turns per conversation, so the
   * second one reads the first one's committed history instead of colliding
   * with it. The unique index stays as the backstop that makes an interrupted
   * retry idempotent rather than duplicating a turn into the model's context.
   *
   * The lock is taken before the policy decision, so a caller Cedar is about to
   * refuse briefly holds it. That is bounded by the immediately following
   * rollback — one statement, no provider call, no tool read — and the
   * alternative (decide, then lock) would read the row twice and decide on the
   * copy that is not the one the turn goes on to use.
   */
  async lockLiveById(tx: Queryable, id: string): Promise<ConversationRow | null> {
    const rows = await tx.query<ConversationRow>(
      `SELECT ${COLUMNS} FROM assistant_conversations
        WHERE id = $1 AND deleted_at IS NULL
        FOR UPDATE`,
      [id],
    );
    return rows[0] ?? null;
  }

  /** The caller's live conversations, most recently active first. */
  async listLiveByUser(q: Queryable | Db, userId: string): Promise<ConversationRow[]> {
    return q.query<ConversationRow>(
      `SELECT ${COLUMNS} FROM assistant_conversations
        WHERE user_id = $1 AND deleted_at IS NULL
        ORDER BY updated_at DESC, id DESC`,
      [userId],
    );
  }

  /**
   * Mark the conversation active. The `set_updated_at` trigger supplies the
   * value; this statement exists to fire it, which is why it sets a column to
   * itself rather than writing `now()` by hand — one definition of "updated"
   * for every writer.
   *
   * The BEFORE UPDATE version trigger therefore captures one
   * `assistant_conversations_versions` row per turn. That cost is accepted
   * deliberately: the captured image is ids and timestamps only (this table
   * holds no content by design), and the row is a per-turn record of activity
   * on the conversation that survives even if the message rows are later
   * crypto-shredded.
   */
  async touch(tx: Queryable, id: string): Promise<void> {
    await tx.query(`UPDATE assistant_conversations SET updated_at = updated_at WHERE id = $1`, [
      id,
    ]);
  }

  /**
   * Soft delete (CLAUDE.md: no hard deletes anywhere). The ciphertext survives;
   * only crypto-shredding the user's assistant DEK actually erases a
   * transcript, which is a separate and separately audited act.
   *
   * The `user_id` predicate is no longer the access decision — Cedar has
   * already answered by the time this runs — but it stays as a data-layer
   * belt-and-braces: a destructive write that can only ever touch the row it
   * was told about costs nothing to keep.
   *
   * Returns false when nothing moved — not the caller's, already deleted, or
   * never existed — all of which the service reports identically.
   */
  async softDelete(tx: Queryable, id: string, userId: string): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE assistant_conversations
          SET deleted_at = now()
        WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
        RETURNING id`,
      [id, userId],
    );
    return rows.length > 0;
  }
}
