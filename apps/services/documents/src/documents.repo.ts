import { Injectable } from '@nestjs/common';
import type { DocType, DocumentSource, ExecutionStatus } from '@estate/contracts';
import { Db, type Queryable } from './db';

export interface DocumentRow {
  id: string;
  user_id: string;
  doc_type: DocType;
  template_id: string | null;
  source: DocumentSource;
  title: string;
  current_version: number;
  execution_status: ExecutionStatus;
  executed_at: string | null;
  legal_hold: boolean;
  sealed: boolean;
  dek_id: string;
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
}

const COLUMNS = `id, user_id, doc_type, template_id, source, title, current_version,
       execution_status, executed_at::text AS executed_at, legal_hold, sealed, dek_id,
       created_at, updated_at, deleted_at`;

/**
 * documents repository — metadata rows; content lives in the object store.
 * Stateless: every method takes the query surface (pool or transaction), so
 * tests can fake it structurally.
 */
@Injectable()
export class DocumentsRepo {
  async getLive(q: Queryable | Db, id: string): Promise<DocumentRow | null> {
    const rows = await q.query<DocumentRow>(
      `SELECT ${COLUMNS} FROM documents WHERE id = $1 AND deleted_at IS NULL`,
      [id],
    );
    return rows[0] ?? null;
  }

  /** Row-lock a live document for the duration of the caller's transaction. */
  async lockById(tx: Queryable, id: string): Promise<DocumentRow | null> {
    const rows = await tx.query<DocumentRow>(
      `SELECT ${COLUMNS} FROM documents WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
      [id],
    );
    return rows[0] ?? null;
  }

  async listLiveByUser(q: Queryable | Db, userId: string): Promise<DocumentRow[]> {
    return q.query<DocumentRow>(
      `SELECT ${COLUMNS} FROM documents
        WHERE user_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC, id DESC`,
      [userId],
    );
  }

  async insert(
    tx: Queryable,
    row: {
      id: string;
      userId: string;
      docType: DocType;
      templateId: string | null;
      source: DocumentSource;
      title: string;
      executionStatus: ExecutionStatus;
      dekId: string;
    },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO documents
         (id, user_id, doc_type, template_id, source, title, current_version,
          execution_status, dek_id)
       VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8)`,
      [
        row.id,
        row.userId,
        row.docType,
        row.templateId,
        row.source,
        row.title,
        row.executionStatus,
        row.dekId,
      ],
    );
  }

  /** Advance to a freshly written content version (status resets to generated). */
  async bumpVersion(tx: Queryable, id: string, version: number): Promise<void> {
    await tx.query(
      `UPDATE documents
          SET current_version = $2, execution_status = 'generated', executed_at = NULL
        WHERE id = $1`,
      [id, version],
    );
  }

  async updateStatus(
    tx: Queryable,
    id: string,
    status: ExecutionStatus,
    executedAt: string | null,
  ): Promise<void> {
    await tx.query(`UPDATE documents SET execution_status = $2, executed_at = $3 WHERE id = $1`, [
      id,
      status,
      executedAt,
    ]);
  }

  async updateTitle(tx: Queryable, id: string, title: string): Promise<void> {
    await tx.query(`UPDATE documents SET title = $2 WHERE id = $1`, [id, title]);
  }

  async softDelete(tx: Queryable, id: string, at: Date): Promise<void> {
    await tx.query(`UPDATE documents SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL`, [
      id,
      at,
    ]);
  }
}
