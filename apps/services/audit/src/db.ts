/**
 * A SINGLE database session (pg `Client` or a checked-out `PoolClient`) —
 * never a `Pool`: the ingestor's BEGIN / SELECT ... FOR UPDATE / COMMIT
 * sequence must run on one connection.
 */
export interface AuditDb {
  query(text: string, values?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>;
}

/** Narrow an untyped driver value to a Buffer (BYTEA columns). */
export function asBuffer(value: unknown, column: string): Buffer {
  if (!Buffer.isBuffer(value)) {
    throw new Error(`expected BYTEA buffer in column '${column}'`);
  }
  return value;
}

/** Narrow a BIGINT column (returned by pg as a decimal string) to a number. */
export function asSeq(value: unknown, column: string): number {
  const n = typeof value === 'string' ? Number(value) : typeof value === 'number' ? value : NaN;
  if (!Number.isSafeInteger(n)) {
    throw new Error(`expected integer sequence in column '${column}'`);
  }
  return n;
}
