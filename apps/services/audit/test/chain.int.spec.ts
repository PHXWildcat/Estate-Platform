import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import type { AuditEvent } from '@estate/contracts';
import { Client } from 'pg';
import { AuditIngestor } from '../src/ingestor';
import { ChainVerifier } from '../src/verifier';
import { makeEvent } from './helpers';

/**
 * Integration tests against a real PostgreSQL instance. Gated on PG_TEST_URL;
 * skipped (but still compiled) when it is not set. Runs in a throwaway scratch
 * schema selected via search_path, dropped afterwards.
 */
const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

jest.setTimeout(30_000);

async function rows(
  client: Client,
  text: string,
  values?: unknown[],
): Promise<Array<Record<string, unknown>>> {
  const res = await client.query<Record<string, unknown>>(text, values);
  return res.rows;
}

describeIfPg('audit chain (integration)', () => {
  const url = process.env['PG_TEST_URL'] ?? '';
  const schema = `audit_it_${randomBytes(4).toString('hex')}`;
  let admin: Client;
  let session: Client;
  let ingestor: AuditIngestor;
  let verifier: ChainVerifier;

  const events: AuditEvent[] = [0, 1, 2, 3, 4].map((i) =>
    makeEvent({
      occurredAt: new Date(Date.UTC(2026, 6, 20, 12, 0, i)).toISOString(),
      detail: { index: i },
    }),
  );

  beforeAll(async () => {
    admin = new Client({ connectionString: url });
    await admin.connect();
    await admin.query(`CREATE SCHEMA "${schema}"`);
    session = new Client({ connectionString: url, options: `-c search_path=${schema}` });
    await session.connect();
    await new Migrator(session, join(__dirname, '..', 'migrations')).migrate();
    ingestor = new AuditIngestor(session);
    // Batch size 2 so five events exercise the streaming/batching path.
    verifier = new ChainVerifier(session, 2);
  });

  afterAll(async () => {
    await session.end();
    await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await admin.end();
  });

  it('ingests five valid events and the chain verifies from genesis', async () => {
    for (const [i, event] of events.entries()) {
      const result = await ingestor.ingest(JSON.stringify(event));
      expect(result).toEqual({ status: 'appended', seq: i + 1 });
    }
    await expect(verifier.verify()).resolves.toEqual({ ok: true, count: 5 });
  });

  it('re-delivering an existing event_id is a duplicate and does not move the chain', async () => {
    const before = await rows(session, 'SELECT head_hash, last_seq FROM audit_chain_head');
    const result = await ingestor.ingest(JSON.stringify(events[2]));
    expect(result).toEqual({ status: 'duplicate' });

    const after = await rows(session, 'SELECT head_hash, last_seq FROM audit_chain_head');
    expect(after[0]?.['last_seq']).toEqual(before[0]?.['last_seq']);
    expect((after[0]?.['head_hash'] as Buffer).equals(before[0]?.['head_hash'] as Buffer)).toBe(
      true,
    );
    await expect(verifier.verify()).resolves.toEqual({ ok: true, count: 5 });
  });

  it('grants PUBLIC no UPDATE or DELETE on the audit tables', async () => {
    // has_table_privilege() cannot be asked about the PUBLIC pseudo-role
    // (it requires an actual role name), so assert via the grants catalog:
    // no UPDATE/DELETE grant rows exist for PUBLIC on either table.
    const grants = await rows(
      session,
      `SELECT count(*) AS n
       FROM information_schema.role_table_grants
       WHERE table_schema = $1
         AND table_name IN ('audit_events', 'audit_events_default')
         AND grantee = 'PUBLIC'
         AND privilege_type IN ('UPDATE', 'DELETE')`,
      [schema],
    );
    expect(Number(grants[0]?.['n'])).toBe(0);
  });

  it('detects tampering with a stored row', async () => {
    // The service role cannot UPDATE (revoked); the table owner used in this
    // test can — which is exactly the insider scenario the hash chain exists
    // to make evident (docs/03: tampering must be detectable, DB writes alone
    // cannot be prevented for the owner).
    await session.query(`UPDATE audit_events SET detail = '{"index":999}'::jsonb WHERE seq = 3`);
    await expect(verifier.verify()).resolves.toEqual({
      ok: false,
      firstBadSeq: 3,
      reason: 'event_hash_mismatch',
    });
  });
});
