import { computeEventHash, GENESIS_HASH } from '../src/chain';
import type { AuditDb } from '../src/db';
import { AuditIngestor } from '../src/ingestor';
import { makeEvent } from './helpers';

interface RecordedCall {
  text: string;
  values: unknown[] | undefined;
}

/**
 * Scripted fake database: records every call and answers by matching the
 * leading SQL keyword/phrase. Throws on anything unscripted so unexpected
 * writes cannot pass silently.
 */
class FakeDb implements AuditDb {
  readonly calls: RecordedCall[] = [];

  constructor(
    private readonly script: Array<{
      match: string;
      rows?: Array<Record<string, unknown>>;
      error?: Error;
    }> = [],
  ) {}

  query(text: string, values?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }> {
    this.calls.push({ text, values });
    const normalized = text.trim().replace(/\s+/g, ' ');
    for (const step of this.script) {
      if (normalized.startsWith(step.match)) {
        if (step.error) {
          return Promise.reject(step.error);
        }
        return Promise.resolve({ rows: step.rows ?? [] });
      }
    }
    // Control statements need no scripting.
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(normalized)) {
      return Promise.resolve({ rows: [] });
    }
    return Promise.reject(new Error(`FakeDb: unscripted query: ${normalized.slice(0, 40)}`));
  }

  callTexts(): string[] {
    return this.calls.map((c) => c.text.trim().replace(/\s+/g, ' ').split(' ')[0] ?? '');
  }
}

function happyPathDb(): FakeDb {
  return new FakeDb([
    {
      match: 'SELECT head_hash, last_seq FROM audit_chain_head',
      rows: [{ head_hash: Buffer.from(GENESIS_HASH), last_seq: '0' }],
    },
    { match: 'SELECT 1 FROM audit_events', rows: [] },
    { match: 'INSERT INTO audit_events', rows: [{ seq: '1' }] },
    { match: 'UPDATE audit_chain_head', rows: [] },
  ]);
}

describe('AuditIngestor', () => {
  it('rejects invalid JSON without touching the database', async () => {
    const db = new FakeDb();
    const result = await new AuditIngestor(db).ingest('{not json');
    expect(result).toEqual({ status: 'rejected', reason: 'invalid_json' });
    expect(db.calls).toHaveLength(0);
  });

  it('rejects schema-violating payloads (PII-shaped detail) without db writes', async () => {
    const db = new FakeDb();
    // '@' and spaces are exactly what the SAFE_TOKEN_PATTERN firewall blocks.
    const payload = JSON.stringify({
      ...makeEvent(),
      detail: { note: 'john doe <johndoe@example.com>' },
    });
    const result = await new AuditIngestor(db).ingest(payload);
    expect(result).toEqual({ status: 'rejected', reason: 'schema_violation' });
    expect(db.calls).toHaveLength(0);
  });

  it('rejects unknown action tokens', async () => {
    const db = new FakeDb();
    const payload = JSON.stringify({ ...makeEvent(), action: 'made.up.action' });
    const result = await new AuditIngestor(db).ingest(payload);
    expect(result).toEqual({ status: 'rejected', reason: 'schema_violation' });
    expect(db.calls).toHaveLength(0);
  });

  it('appends a valid event inside one transaction with the correct hash', async () => {
    const db = happyPathDb();
    const event = makeEvent();
    const result = await new AuditIngestor(db).ingest(JSON.stringify(event));
    expect(result).toEqual({ status: 'appended', seq: 1 });

    expect(db.callTexts()).toEqual(['BEGIN', 'SELECT', 'SELECT', 'INSERT', 'UPDATE', 'COMMIT']);

    const insert = db.calls[3];
    const expectedHash = computeEventHash(GENESIS_HASH, event);
    expect(insert?.values?.[0]).toBe(event.eventId);
    expect((insert?.values?.[11] as Buffer).equals(expectedHash)).toBe(true);

    const headUpdate = db.calls[4];
    expect(headUpdate?.values?.[0]).toBe(1);
    expect((headUpdate?.values?.[1] as Buffer).equals(expectedHash)).toBe(true);
  });

  it('normalizes occurredAt to millisecond ISO-8601 UTC before hashing/storing', async () => {
    const db = happyPathDb();
    const event = makeEvent({ occurredAt: '2026-07-20T12:00:00Z' }); // no ms
    await new AuditIngestor(db).ingest(JSON.stringify(event));
    const insert = db.calls[3];
    expect(insert?.values?.[1]).toBe('2026-07-20T12:00:00.000Z');
    const normalized = { ...event, occurredAt: '2026-07-20T12:00:00.000Z' };
    const expectedHash = computeEventHash(GENESIS_HASH, normalized);
    expect((insert?.values?.[11] as Buffer).equals(expectedHash)).toBe(true);
  });

  it('returns duplicate and rolls back without inserting or moving the head', async () => {
    const db = new FakeDb([
      {
        match: 'SELECT head_hash, last_seq FROM audit_chain_head',
        rows: [{ head_hash: Buffer.from(GENESIS_HASH), last_seq: '7' }],
      },
      { match: 'SELECT 1 FROM audit_events', rows: [{ exists: 1 }] },
    ]);
    const result = await new AuditIngestor(db).ingest(JSON.stringify(makeEvent()));
    expect(result).toEqual({ status: 'duplicate' });
    expect(db.callTexts()).toEqual(['BEGIN', 'SELECT', 'SELECT', 'ROLLBACK']);
  });

  it('rolls back and rethrows on a database failure mid-transaction', async () => {
    const db = new FakeDb([
      {
        match: 'SELECT head_hash, last_seq FROM audit_chain_head',
        rows: [{ head_hash: Buffer.from(GENESIS_HASH), last_seq: '0' }],
      },
      { match: 'SELECT 1 FROM audit_events', rows: [] },
      { match: 'INSERT INTO audit_events', error: new Error('connection lost') },
    ]);
    await expect(new AuditIngestor(db).ingest(JSON.stringify(makeEvent()))).rejects.toThrow(
      'connection lost',
    );
    expect(db.callTexts().at(-1)).toBe('ROLLBACK');
  });
});
