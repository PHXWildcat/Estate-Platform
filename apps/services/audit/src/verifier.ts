import { AuditEventSchema } from '@estate/contracts';
import { computeEventHash, GENESIS_HASH } from './chain';
import { asBuffer, asSeq, type AuditDb } from './db';

export type VerifyFailureReason = 'prev_hash_mismatch' | 'event_hash_mismatch' | 'head_mismatch';

export type VerifyResult =
  { ok: true; count: number } | { ok: false; firstBadSeq: number; reason: VerifyFailureReason };

const SELECT_BATCH_SQL = `
SELECT seq, event_id, occurred_at, actor_id, actor_type, on_behalf_of, action,
       resource_type, resource_id, session_id, detail, prev_hash, event_hash
FROM audit_events
WHERE seq > $1
ORDER BY seq
LIMIT $2`;

/**
 * Recomputes the whole hash chain from GENESIS_HASH and compares it to what
 * is stored — row by row (prev_hash linkage and event_hash), then against
 * `audit_chain_head`. Streams in seq-ordered batches so verification is
 * O(batch) in memory regardless of chain length.
 *
 * Rows are re-canonicalized from their stored columns; this only works
 * because the ingestor hashes the normalized, storage-equivalent form of the
 * event (see AuditIngestor / canonicalize doc comments).
 */
export class ChainVerifier {
  constructor(
    private readonly db: AuditDb,
    private readonly batchSize: number = 500,
  ) {}

  async verify(): Promise<VerifyResult> {
    let running = GENESIS_HASH;
    let lastSeq = 0;
    let count = 0;

    for (;;) {
      const { rows } = await this.db.query(SELECT_BATCH_SQL, [lastSeq, this.batchSize]);
      if (rows.length === 0) {
        break;
      }
      for (const row of rows) {
        const seq = asSeq(row['seq'], 'seq');
        const storedPrev = asBuffer(row['prev_hash'], 'prev_hash');
        if (!storedPrev.equals(running)) {
          return { ok: false, firstBadSeq: seq, reason: 'prev_hash_mismatch' };
        }
        const recomputed = this.recomputeHash(running, row);
        if (recomputed === null) {
          // Row content no longer parses as a valid audit event — it cannot
          // be what was originally hashed.
          return { ok: false, firstBadSeq: seq, reason: 'event_hash_mismatch' };
        }
        const storedHash = asBuffer(row['event_hash'], 'event_hash');
        if (!recomputed.equals(storedHash)) {
          return { ok: false, firstBadSeq: seq, reason: 'event_hash_mismatch' };
        }
        running = recomputed;
        lastSeq = seq;
        count += 1;
      }
    }

    const head = await this.db.query('SELECT head_hash, last_seq FROM audit_chain_head');
    const headRow = head.rows[0];
    if (headRow === undefined) {
      return { ok: false, firstBadSeq: lastSeq, reason: 'head_mismatch' };
    }
    const headHash = asBuffer(headRow['head_hash'], 'head_hash');
    const headSeq = asSeq(headRow['last_seq'], 'last_seq');
    if (!headHash.equals(running) || headSeq !== lastSeq) {
      return { ok: false, firstBadSeq: lastSeq, reason: 'head_mismatch' };
    }
    return { ok: true, count };
  }

  /** Rebuild the normalized event from a row and hash it; null if invalid. */
  private recomputeHash(prevHash: Buffer, row: Record<string, unknown>): Buffer | null {
    const occurredAt = row['occurred_at'];
    if (!(occurredAt instanceof Date)) {
      return null;
    }
    const candidate = {
      eventId: row['event_id'],
      occurredAt: occurredAt.toISOString(),
      action: row['action'],
      actorId: row['actor_id'],
      actorType: row['actor_type'],
      onBehalfOf: row['on_behalf_of'],
      resourceType: row['resource_type'],
      resourceId: row['resource_id'],
      sessionId: row['session_id'],
      detail: row['detail'],
    };
    const parsed = AuditEventSchema.safeParse(candidate);
    if (!parsed.success) {
      return null;
    }
    return computeEventHash(prevHash, parsed.data);
  }
}
