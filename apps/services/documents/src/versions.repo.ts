import { Injectable } from '@nestjs/common';
import { Db, type Queryable } from './db';

export interface VersionRow {
  id: string;
  document_id: string;
  version: number;
  object_key: string;
  content_sha256: Buffer;
  size_bytes: string; // BIGINT comes back as string
  mime: string;
  ocr_indexed: boolean;
  created_by: string;
  created_at: Date;
}

const COLUMNS = `id, document_id, version, object_key, content_sha256, size_bytes::text AS size_bytes,
       mime, ocr_indexed, created_by, created_at`;

/**
 * document_versions repository — the append-only, content-addressed version
 * history. INSERT and SELECT only; the table REVOKEs UPDATE/DELETE.
 */
@Injectable()
export class VersionsRepo {
  async insert(
    tx: Queryable,
    row: {
      documentId: string;
      version: number;
      objectKey: string;
      contentSha256: Buffer;
      sizeBytes: number;
      mime: string;
      createdBy: string;
    },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO document_versions
         (document_id, version, object_key, content_sha256, size_bytes, mime, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        row.documentId,
        row.version,
        row.objectKey,
        row.contentSha256,
        row.sizeBytes,
        row.mime,
        row.createdBy,
      ],
    );
  }

  async listByDocument(q: Queryable | Db, documentId: string): Promise<VersionRow[]> {
    return q.query<VersionRow>(
      `SELECT ${COLUMNS} FROM document_versions WHERE document_id = $1 ORDER BY version`,
      [documentId],
    );
  }

  async getByVersion(
    q: Queryable | Db,
    documentId: string,
    version: number,
  ): Promise<VersionRow | null> {
    const rows = await q.query<VersionRow>(
      `SELECT ${COLUMNS} FROM document_versions WHERE document_id = $1 AND version = $2`,
      [documentId, version],
    );
    return rows[0] ?? null;
  }
}
