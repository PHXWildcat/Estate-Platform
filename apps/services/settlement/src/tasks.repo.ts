import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

export interface TaskRow {
  id: string;
  case_id: string;
  title: string;
  category: string | null;
  assigned_role: string | null;
  due_at: Date | null;
  completed_at: Date | null;
  completed_by: string | null;
  court_doc_version_id: string | null;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = `id, case_id, title, category, assigned_role, due_at,
       completed_at, completed_by, court_doc_version_id, created_at, updated_at`;

/**
 * settlement_tasks (docs/02 §7) — the estate checklist. Titles are template
 * text (in-repo, versioned like code), never user PII, so they are plaintext
 * like `assets_view.title`.
 */
@Injectable()
export class TasksRepo {
  /** Bulk-insert the generated checklist in one statement. */
  async insertMany(
    tx: Queryable,
    caseId: string,
    tasks: ReadonlyArray<{
      title: string;
      category: string | null;
      assignedRole: string | null;
      dueAt: Date | null;
    }>,
  ): Promise<number> {
    if (tasks.length === 0) {
      return 0;
    }
    const values: unknown[] = [caseId];
    const tuples = tasks.map((t, i) => {
      const base = i * 4 + 2;
      values.push(t.title, t.category, t.assignedRole, t.dueAt);
      return `($1, $${base}, $${base + 1}, $${base + 2}, $${base + 3})`;
    });
    const rows = await tx.query<{ id: string }>(
      `INSERT INTO settlement_tasks (case_id, title, category, assigned_role, due_at)
       VALUES ${tuples.join(', ')}
       RETURNING id`,
      values,
    );
    return rows.length;
  }

  async listByCase(q: Queryable | Db, caseId: string): Promise<TaskRow[]> {
    return q.query<TaskRow>(
      `SELECT ${COLUMNS} FROM settlement_tasks
        WHERE case_id = $1 AND deleted_at IS NULL
        ORDER BY due_at NULLS LAST, created_at, id`,
      [caseId],
    );
  }

  async countByCase(q: Queryable | Db, caseId: string): Promise<number> {
    const rows = await q.query<{ n: string }>(
      `SELECT COUNT(*) AS n FROM settlement_tasks
        WHERE case_id = $1 AND deleted_at IS NULL`,
      [caseId],
    );
    return Number(rows[0]?.n ?? 0);
  }

  async lockById(tx: Queryable, taskId: string): Promise<TaskRow | null> {
    const rows = await tx.query<TaskRow>(
      `SELECT ${COLUMNS} FROM settlement_tasks
        WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
      [taskId],
    );
    return rows[0] ?? null;
  }

  /** Complete (or re-open, with completedAt null) a task. */
  async setCompletion(
    tx: Queryable,
    taskId: string,
    completion: { at: Date; by: string } | null,
    courtDocVersionId: string | null,
  ): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE settlement_tasks
          SET completed_at = $2,
              completed_by = $3,
              court_doc_version_id = COALESCE($4, court_doc_version_id)
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING id`,
      [taskId, completion?.at ?? null, completion?.by ?? null, courtDocVersionId],
    );
    return rows.length > 0;
  }
}
