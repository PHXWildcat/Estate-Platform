import { AuditEventSchema, type AuditEvent } from '@estate/contracts';
import { computeEventHash } from './chain';
import { asBuffer, asSeq, type AuditDb } from './db';

/**
 * Rejection reasons are a closed enum — the raw payload (which may contain
 * exactly the PII the schema rejected) is never echoed into results, logs,
 * or error messages. Callers may record topic/partition/offset only.
 */
export type RejectReason = 'invalid_json' | 'schema_violation';

export type IngestResult =
  | { status: 'appended'; seq: number }
  | { status: 'duplicate' }
  | { status: 'rejected'; reason: RejectReason };

const INSERT_EVENT_SQL = `
INSERT INTO audit_events
  (event_id, occurred_at, actor_id, actor_type, on_behalf_of, action,
   resource_type, resource_id, session_id, device_id, ip_ct, geo, user_agent,
   detail, prev_hash, event_hash)
VALUES
  ($1, $2::timestamptz, $3, $4, $5, $6,
   $7, $8, $9, NULL, NULL, NULL, NULL,
   $10::jsonb, $11, $12)
RETURNING seq`;

/**
 * Appends validated audit events to the hash-chained store.
 *
 * Every append runs in a single transaction on the dedicated session:
 * the `audit_chain_head` row lock (SELECT ... FOR UPDATE) serializes chain
 * extension, so the chain never forks even with concurrent ingestors.
 *
 * The hash is computed over the event in its NORMALIZED, storage-equivalent
 * form: `occurredAt` is reduced to millisecond-precision ISO-8601 UTC (what
 * `Date.prototype.toISOString` yields) before hashing AND before insert, so
 * the verifier can rebuild identical canonical bytes from database rows.
 */
export class AuditIngestor {
  constructor(private readonly db: AuditDb) {}

  async ingest(rawValue: string): Promise<IngestResult> {
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawValue) as unknown;
    } catch {
      return { status: 'rejected', reason: 'invalid_json' };
    }

    const parsed = AuditEventSchema.safeParse(parsedJson);
    if (!parsed.success) {
      return { status: 'rejected', reason: 'schema_violation' };
    }

    const event: AuditEvent = {
      ...parsed.data,
      occurredAt: new Date(parsed.data.occurredAt).toISOString(),
    };

    await this.db.query('BEGIN');
    try {
      const head = await this.db.query(
        'SELECT head_hash, last_seq FROM audit_chain_head FOR UPDATE',
      );
      const headRow = head.rows[0];
      if (headRow === undefined) {
        throw new Error('audit_chain_head is empty — run migrations before ingesting');
      }
      const prevHash = asBuffer(headRow['head_hash'], 'head_hash');

      const dup = await this.db.query('SELECT 1 FROM audit_events WHERE event_id = $1 LIMIT 1', [
        event.eventId,
      ]);
      if (dup.rows.length > 0) {
        await this.db.query('ROLLBACK');
        return { status: 'duplicate' };
      }

      const eventHash = computeEventHash(prevHash, event);
      const inserted = await this.db.query(INSERT_EVENT_SQL, [
        event.eventId,
        event.occurredAt,
        event.actorId,
        event.actorType,
        event.onBehalfOf,
        event.action,
        event.resourceType,
        event.resourceId,
        event.sessionId,
        JSON.stringify(event.detail),
        prevHash,
        eventHash,
      ]);
      const seq = asSeq(inserted.rows[0]?.['seq'], 'seq');

      await this.db.query(
        'UPDATE audit_chain_head SET last_seq = $1, head_hash = $2, updated_at = now() WHERE id',
        [seq, eventHash],
      );
      await this.db.query('COMMIT');
      return { status: 'appended', seq };
    } catch (err) {
      await this.db.query('ROLLBACK');
      throw err;
    }
  }
}
