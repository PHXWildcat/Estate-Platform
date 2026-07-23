import { Injectable } from '@nestjs/common';
import type { DocType, UsState } from '@estate/contracts';
import { Db, type Queryable } from './db';

export interface TemplateRow {
  id: string;
  doc_type: DocType;
  state: UsState;
  version: number;
  body_ref: string;
  body_sha256: Buffer;
  legal_review_by: string;
  legal_review_at: Date;
  execution_requirements: unknown;
  variables: unknown;
  active: boolean;
  created_at: Date;
  deleted_at: Date | null;
}

const COLUMNS = `id, doc_type, state, version, body_ref, body_sha256,
       legal_review_by, legal_review_at, execution_requirements, variables,
       active, created_at, deleted_at`;

/**
 * document_templates repository. Rows are written ONLY by the publish CLI
 * (in-repo sources, sign-off gated); the service reads them to resolve and
 * render. A published (doc_type, state, version) row's content columns are
 * immutable — the only runtime mutation is the active flag, captured by the
 * versions shadow table with actor attribution. Stateless: every method takes
 * the query surface (pool or transaction), so tests can fake it structurally.
 */
@Injectable()
export class TemplatesRepo {
  /** The single active template for a (docType, state) pair, if any. */
  async findActive(
    q: Queryable | Db,
    docType: DocType,
    state: UsState,
  ): Promise<TemplateRow | null> {
    const rows = await q.query<TemplateRow>(
      `SELECT ${COLUMNS} FROM document_templates
        WHERE doc_type = $1 AND state = $2 AND active AND deleted_at IS NULL`,
      [docType, state],
    );
    return rows[0] ?? null;
  }

  async findById(q: Queryable | Db, id: string): Promise<TemplateRow | null> {
    const rows = await q.query<TemplateRow>(
      `SELECT ${COLUMNS} FROM document_templates WHERE id = $1 AND deleted_at IS NULL`,
      [id],
    );
    return rows[0] ?? null;
  }

  /** Template catalog for a state (active only): what can be generated. */
  async listActiveByState(q: Queryable | Db, state: UsState): Promise<TemplateRow[]> {
    return q.query<TemplateRow>(
      `SELECT ${COLUMNS} FROM document_templates
        WHERE state = $1 AND active AND deleted_at IS NULL
        ORDER BY doc_type`,
      [state],
    );
  }
}

// ---------------------------------------------------------------- publish CLI
// Queryable-based write functions used only by template-publish-cli.ts (the
// service itself never mutates templates at runtime).

export async function findTemplateByKey(
  q: Queryable,
  docType: DocType,
  state: UsState,
  version: number,
): Promise<TemplateRow | null> {
  const rows = await q.query<TemplateRow>(
    `SELECT ${COLUMNS} FROM document_templates
      WHERE doc_type = $1 AND state = $2 AND version = $3`,
    [docType, state, version],
  );
  return rows[0] ?? null;
}

export async function insertTemplate(
  q: Queryable,
  row: {
    docType: DocType;
    state: UsState;
    version: number;
    bodyRef: string;
    bodySha256: Buffer;
    legalReviewBy: string;
    legalReviewAt: Date;
    executionRequirements: unknown;
    variables: unknown;
  },
): Promise<string> {
  const inserted = await q.query<{ id: string }>(
    `INSERT INTO document_templates
       (doc_type, state, version, body_ref, body_sha256,
        legal_review_by, legal_review_at, execution_requirements, variables, active)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false)
     RETURNING id`,
    [
      row.docType,
      row.state,
      row.version,
      row.bodyRef,
      row.bodySha256,
      row.legalReviewBy,
      row.legalReviewAt,
      JSON.stringify(row.executionRequirements),
      JSON.stringify(row.variables),
    ],
  );
  return inserted[0]!.id;
}

/**
 * Make `id` the single active version for its (docType, state): deactivate
 * the incumbent, then activate. Runs inside the caller's transaction so the
 * partial unique index never sees two actives.
 */
export async function activateTemplate(
  q: Queryable,
  id: string,
  docType: DocType,
  state: UsState,
): Promise<void> {
  await q.query(
    `UPDATE document_templates SET active = false
      WHERE doc_type = $1 AND state = $2 AND active AND deleted_at IS NULL AND id <> $3`,
    [docType, state, id],
  );
  await q.query(`UPDATE document_templates SET active = true WHERE id = $1 AND NOT active`, [id]);
}
