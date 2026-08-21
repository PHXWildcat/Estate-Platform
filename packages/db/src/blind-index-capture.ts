/**
 * DOES THE DEPLOYED CAPTURE FUNCTION ACTUALLY DROP THE BLIND INDEX? (M25 PR1)
 *
 * The static half of this rule lives in
 * `packages/contracts/test/version-capture-redaction.spec.ts`, which reads the
 * migration SQL and proves a redaction was WRITTEN. This is the other half: it
 * asks the DATABASE what function it is running, so a migration that was
 * written and never applied, applied to the wrong schema, or superseded by a
 * later `CREATE OR REPLACE` that lost the redaction, is caught.
 *
 * WHY IT LIVES HERE AND NOT IN EACH SERVICE. Three services need it today and
 * a fourth needs it the moment it adds a blind index to a versioned table.
 * Eleven packages once carried their own copy of the CI guard and the wording
 * had drifted in every one of them while nothing tested the assertion anywhere
 * — the rule this repo settled on is that the check lives in one package and
 * the services call it. `@estate/config/ci-guard` is the precedent.
 *
 * DERIVED FROM THE LIVE SCHEMA, never a table list. The corpus is every table
 * in the schema that has BOTH a `*_bidx` column and a `<table>_versions`
 * shadow, read out of `information_schema` — the same predicate the static
 * fence derives from the migrations, asked of the running database instead. A
 * service that adds a blind index to a versioned table is covered without
 * anyone editing this file.
 *
 * WHAT IT DOES NOT PROVE. That the trigger FIRES — a function can be perfect
 * and unattached. The trigger's existence is the `_versions` convention's own
 * business (`checkConventions`), and identity's `password-change.int.spec.ts`
 * proves the whole chain end to end on the one table where it matters most, by
 * driving a real service UPDATE and reading the captured image back.
 */
import type { Client } from 'pg';

/** One table whose deployed capture function does not redact blind indexes. */
export interface BlindIndexCaptureGap {
  readonly table: string;
  /** The blind-index columns that would be captured. */
  readonly columns: readonly string[];
  readonly reason: 'no_capture_function' | 'no_redaction';
}

/**
 * The corpus: tables in `schema` carrying both a `*_bidx` column and a
 * capturing `<table>_versions` shadow. Exported so a caller can assert the
 * corpus is NON-EMPTY before believing an empty gap list — a check whose input
 * is empty and a check that passes look identical.
 */
export async function blindIndexCaptureCorpus(
  client: Client,
  schema: string,
): Promise<Map<string, string[]>> {
  const { rows } = await client.query<{ table_name: string; column_name: string }>(
    `SELECT c.table_name, c.column_name
       FROM information_schema.columns c
      WHERE c.table_schema = $1
        AND right(c.column_name, 5) = '_bidx'
        AND EXISTS (
              SELECT 1 FROM information_schema.tables t
               WHERE t.table_schema = $1
                 AND t.table_name = c.table_name || '_versions')
      ORDER BY c.table_name, c.column_name`,
    [schema],
  );
  const corpus = new Map<string, string[]>();
  for (const row of rows) {
    const existing = corpus.get(row.table_name);
    if (existing === undefined) {
      corpus.set(row.table_name, [row.column_name]);
    } else {
      existing.push(row.column_name);
    }
  }
  return corpus;
}

/**
 * Tables in `schema` whose deployed `<table>_capture_version` does not drop
 * blind indexes. Empty is the passing answer — pair it with a corpus-size
 * assertion, or an empty schema passes vacuously.
 *
 * The redaction is recognised by what the function BODY does with the image's
 * own keys, not by a column name: a body naming `email_bidx` literally would
 * leave the next blind index on that table captured, so it is deliberately NOT
 * accepted here.
 */
export async function blindIndexCaptureGaps(
  client: Client,
  schema: string,
): Promise<BlindIndexCaptureGap[]> {
  const corpus = await blindIndexCaptureCorpus(client, schema);
  const gaps: BlindIndexCaptureGap[] = [];

  for (const [table, columns] of corpus) {
    const { rows } = await client.query<{ def: string }>(
      `SELECT pg_get_functiondef(p.oid) AS def
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = $1 AND p.proname = $2`,
      [schema, `${table}_capture_version`],
    );
    const def = rows[0]?.def;
    if (def === undefined) {
      gaps.push({ table, columns, reason: 'no_capture_function' });
      continue;
    }
    const derivesKeys = /jsonb_object_keys/i.test(def);
    const dropsBidx = /right\s*\(\s*k\s*,\s*5\s*\)\s*=\s*'_bidx'/i.test(def);
    if (!derivesKeys || !dropsBidx) {
      gaps.push({ table, columns, reason: 'no_redaction' });
    }
  }
  return gaps;
}
