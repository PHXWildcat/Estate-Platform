import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

/**
 * Read side of `assistant_tool_calls` (M10 security review).
 *
 * The table is WRITTEN by `ToolExecutor`, inside the turn's own transaction, and
 * until now nothing read it back: it existed as evidence. The review found a
 * reason to read it — the privacy proxy's placeholder map lives for one turn, so
 * a title tokenized in turn 1 was shipped in the clear in turn 2's replayed
 * history. Re-deriving the map needs the values those earlier retrievals
 * returned, which is exactly what this table holds (encrypted, AAD-bound to the
 * tool-call id).
 *
 * ONLY SUCCESSFUL RETRIEVALS ARE SELECTED. A denial or an error carries no
 * ciphertext at all (the DDL's pair CHECK says so, and the executor honours it),
 * so `result_ct IS NOT NULL` is the shape of the table rather than a filter
 * anyone has to remember. `tool_name` comes back with it because the
 * tokenization rules are keyed by tool.
 *
 * Ownership is NOT re-checked here, for the reason `MessagesRepo` gives: the
 * only way to hold a conversation id is through `ConversationsRepo`, whose every
 * predicate carries the owner, and a second weaker check invites reliance on it.
 */

export interface ToolCallResultRow {
  id: string;
  tool_name: string;
  result_ct: Buffer;
  dek_id: string;
}

@Injectable()
export class ToolCallsRepo {
  /**
   * Every successful retrieval in one conversation, oldest first.
   *
   * Ordered by `created_at, id` so the placeholder numbering a replay derives is
   * deterministic — ⟦ASSET_1⟧ has to mean the same asset every time a
   * conversation is continued, or the model sees one numbering in the history
   * and another in this turn's results.
   */
  async listResultsByConversation(
    q: Queryable | Db,
    conversationId: string,
  ): Promise<ToolCallResultRow[]> {
    return q.query<ToolCallResultRow>(
      `SELECT id, tool_name, result_ct, dek_id
         FROM assistant_tool_calls
        WHERE conversation_id = $1
          AND result_ct IS NOT NULL
        ORDER BY created_at ASC, id ASC`,
      [conversationId],
    );
  }
}
