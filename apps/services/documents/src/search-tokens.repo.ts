import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

/**
 * document_search_tokens repository — the derived encrypted search index.
 * Replace-in-place on (re)index is sanctioned: this table is a rebuildable
 * projection of encrypted content, exempt from the soft-delete conventions
 * (see 002_document_vault.sql). Stateless like the other repos.
 */
@Injectable()
export class SearchTokensRepo {
  /** Replace a document's index rows with the given token HMACs. */
  async replaceForDocument(tx: Queryable, documentId: string, tokens: Buffer[]): Promise<void> {
    await tx.query(`DELETE FROM document_search_tokens WHERE document_id = $1`, [documentId]);
    for (const token of tokens) {
      // ON CONFLICT: tokenize() dedupes, but stay idempotent by construction.
      await tx.query(
        `INSERT INTO document_search_tokens (document_id, token_bidx)
         VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [documentId, token],
      );
    }
  }

  /**
   * Documents of `userId` whose index contains ALL the given token HMACs
   * (AND semantics), excluding soft-deleted documents at query time.
   */
  async findMatchingAll(q: Queryable | Db, userId: string, tokens: Buffer[]): Promise<string[]> {
    if (tokens.length === 0) {
      return [];
    }
    const rows = await q.query<{ document_id: string }>(
      `SELECT t.document_id
         FROM document_search_tokens t
         JOIN documents d ON d.id = t.document_id
        WHERE d.user_id = $1 AND d.deleted_at IS NULL AND t.token_bidx = ANY($2)
        GROUP BY t.document_id
       HAVING count(DISTINCT t.token_bidx) = $3
        ORDER BY t.document_id`,
      [userId, tokens, tokens.length],
    );
    return rows.map((r) => r.document_id);
  }
}
