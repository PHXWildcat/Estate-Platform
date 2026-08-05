import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

/** A message role. Mirrors the `assistant_messages.role` CHECK exactly. */
export type MessageRole = 'user' | 'assistant';

export interface MessageRow {
  id: string;
  conversation_id: string;
  seq: number;
  role: MessageRole;
  content_ct: Buffer;
  dek_id: string;
  created_at: Date;
}

const COLUMNS = 'id, conversation_id, seq, role, content_ct, dek_id, created_at';

/**
 * `assistant_messages` — the append-only turn log. There is no update method
 * and no delete method on this class, and the table has UPDATE/DELETE revoked
 * besides: the rows ARE the history (the `notification_sends` precedent).
 *
 * Bodies are AEAD ciphertext under the owner's per-user DEK, with the AAD bound
 * to the MESSAGE ID (see `field-cipher.ts`). That binding is what makes the
 * plaintext `conversation_id`, `seq` and `role` columns here trustworthy: a
 * database-tamper adversary (docs/03 TB4) who moves a row to another
 * conversation, reorders a transcript, or relabels a user turn as an assistant
 * turn leaves ciphertext that no longer opens, so a forged record of what the
 * assistant was asked or answered fails to decrypt rather than reading as true.
 *
 * Ownership is NOT re-checked here. Every method is keyed by conversation id,
 * and the caller reaches a conversation id only through `ConversationsRepo`,
 * whose every predicate carries the owner — a second, weaker check on this side
 * would invite someone to rely on it instead.
 */
@Injectable()
export class MessagesRepo {
  /**
   * The whole conversation in turn order. Ordered by `seq` rather than by
   * `created_at`: seq is the conversation's spine and is UNIQUE per
   * conversation, while two rows written inside one transaction can share a
   * timestamp to the microsecond, and a transcript whose order depends on a
   * tie-break is not a transcript.
   */
  async listByConversation(q: Queryable | Db, conversationId: string): Promise<MessageRow[]> {
    return q.query<MessageRow>(
      `SELECT ${COLUMNS} FROM assistant_messages
        WHERE conversation_id = $1
        ORDER BY seq ASC`,
      [conversationId],
    );
  }

  /**
   * Append one turn. The id is supplied by the caller because the AAD binds it
   * — the ciphertext must be sealed against the id it will be stored under, so
   * the id has to exist before the encryption, not come back from the INSERT.
   *
   * A duplicate (conversation_id, seq) raises 23505, which the service maps to
   * a conflict rather than a 500: it means another turn committed first, and
   * the honest answer is "try again", never a silently renumbered turn.
   */
  async insert(
    tx: Queryable,
    row: {
      id: string;
      conversationId: string;
      seq: number;
      role: MessageRole;
      contentCt: Buffer;
      dekId: string;
    },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO assistant_messages (id, conversation_id, seq, role, content_ct, dek_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [row.id, row.conversationId, row.seq, row.role, row.contentCt, row.dekId],
    );
  }
}
