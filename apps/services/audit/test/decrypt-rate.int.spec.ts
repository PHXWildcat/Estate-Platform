import { randomBytes, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { AuditEmitter } from '@estate/audit-emitter';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AuditEventSchema } from '@estate/contracts';
import { Client } from 'pg';
import { AuditIngestor } from '../src/ingestor';
import { ChainVerifier } from '../src/verifier';
import { DecryptRateDetector } from '../src/decrypt-rate-detector';
import { boundFor } from '../src/decrypt-rate-bounds';
import { makeEvent } from './helpers';

/**
 * The M18 detector against real Postgres, through the REAL ingestor — you
 * cannot seed audit_events directly (a direct INSERT breaks the hash chain),
 * so every synthetic decrypt goes through the same serialized chain append
 * production events take, and the emitted anomaly is fed BACK through the
 * ingestor to prove the chain accepts what the detector produces.
 *
 * One scratch schema, ONE detector instance across the cases (episode state
 * is the thing under test — a fresh detector per case would re-announce old
 * episodes and turn every count into noise); cases assert message DELTAS.
 */
const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

jest.setTimeout(60_000);

const NOW = new Date('2026-08-13T12:00:00.000Z');
const IN_WINDOW = new Date(NOW.getTime() - 60_000).toISOString();

describeIfPg('decrypt-rate detector (integration)', () => {
  const url = process.env['PG_TEST_URL'] ?? '';
  const schema = `audit_rate_${randomBytes(4).toString('hex')}`;
  let admin: Client;
  let session: Client;
  let ingestor: AuditIngestor;
  let verifier: ChainVerifier;
  let producer: InMemoryAuditProducer;
  let detector: DecryptRateDetector;
  let clockNow = NOW;

  const mfaMax = boundFor('mfa_methods', 'user').maxPerWindow;
  const burstUser = randomUUID();
  const quietUser = randomUUID();

  beforeAll(async () => {
    admin = new Client({ connectionString: url });
    await admin.connect();
    await admin.query(`CREATE SCHEMA "${schema}"`);
    session = new Client({ connectionString: url, options: `-c search_path=${schema}` });
    await session.connect();
    await new Migrator(session, join(__dirname, '..', 'migrations')).migrate();
    ingestor = new AuditIngestor(session);
    verifier = new ChainVerifier(session, 50);
    producer = new InMemoryAuditProducer();
    detector = new DecryptRateDetector(session, new AuditEmitter(producer), () => clockNow);
  });

  afterAll(async () => {
    await session.end();
    await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await admin.end();
  });

  async function ingestDecrypts(
    n: number,
    over: {
      field: string;
      actorId: string;
      actorType?: 'user' | 'service' | 'operator' | 'system';
    },
  ): Promise<void> {
    for (let i = 0; i < n; i++) {
      const result = await ingestor.ingest(
        JSON.stringify(
          makeEvent({
            action: 'crypto.field.decrypted',
            actorType: over.actorType ?? 'user',
            actorId: over.actorId,
            resourceType: 'field',
            occurredAt: IN_WINDOW,
            detail: { dekId: randomUUID(), field: over.field, purpose: 'int_probe' },
          }),
        ),
      );
      expect(result).toMatchObject({ status: 'appended' });
    }
  }

  it('a burst one over the bound emits exactly one schema-valid anomaly about that principal', async () => {
    await ingestDecrypts(mfaMax + 1, { field: 'mfa_methods.totp_secret', actorId: burstUser });
    await detector.tick();
    expect(producer.messages).toHaveLength(1);
    const event = AuditEventSchema.parse(JSON.parse(producer.messages[0]?.value ?? ''));
    expect(event.action).toBe('crypto.decrypt_rate.exceeded');
    expect(event.resourceId).toBe(burstUser);
    expect(event.detail).toMatchObject({
      boundName: 'mfa_methods_user',
      prefixClass: 'mfa_methods',
      principal: 'user',
      count: mfaMax + 1,
    });
  });

  it('the chain ACCEPTS the anomaly the detector produced (the loop closes)', async () => {
    // Same bytes the producer sent — this is the deploy-order story made
    // structural: emitter and consumer are one image, and the consumer's
    // schema admits what the detector emits.
    const result = await ingestor.ingest(producer.messages[0]?.value ?? '');
    expect(result).toMatchObject({ status: 'appended' });
    await expect(verifier.verify()).resolves.toMatchObject({ ok: true });
  });

  it('a sustained breach stays ONE episode across ticks', async () => {
    await detector.tick();
    await detector.tick();
    expect(producer.messages).toHaveLength(1);
  });

  it('a principal AT the bound is silent (the boundary, against the real index)', async () => {
    await ingestDecrypts(mfaMax, { field: 'mfa_methods.totp_secret', actorId: quietUser });
    await detector.tick();
    expect(producer.messages).toHaveLength(1); // no new message
  });

  it('one decrypt under an UNREGISTERED prefix is its own reportable class', async () => {
    await ingestDecrypts(1, { field: 'trust.name', actorId: randomUUID() });
    await detector.tick();
    expect(producer.messages).toHaveLength(2);
    const event = AuditEventSchema.parse(JSON.parse(producer.messages[1]?.value ?? ''));
    expect(event.detail).toMatchObject({
      boundName: 'unknown_prefix',
      prefixClass: 'trust',
      count: 1,
    });
  });

  it('one decrypt under an encrypt-only prefix breaches immediately', async () => {
    await ingestDecrypts(1, { field: 'distributions.amount', actorId: randomUUID() });
    await detector.tick();
    expect(producer.messages).toHaveLength(3);
    const event = AuditEventSchema.parse(JSON.parse(producer.messages[2]?.value ?? ''));
    expect(event.detail).toMatchObject({ boundName: 'encrypt_only', prefixClass: 'distributions' });
  });

  it('the sentinel rides its own bound; a REAL service principal under the same prefix is unmodeled', async () => {
    const sentinel = '00000000-0000-0000-0000-000000000000';
    // Well under the sentinel bound: must stay silent. If the sentinel were
    // folded into 'service', this would breach unmodeled_principal at 1.
    await ingestDecrypts(3, {
      field: 'notification_recipient.email',
      actorId: sentinel,
      actorType: 'service',
    });
    await detector.tick();
    expect(producer.messages).toHaveLength(3);
    // A real id with actorType service has no modelled bound: loud at one.
    const realService = randomUUID();
    await ingestDecrypts(1, {
      field: 'notification_recipient.email',
      actorId: realService,
      actorType: 'service',
    });
    await detector.tick();
    expect(producer.messages).toHaveLength(4);
    const event = AuditEventSchema.parse(JSON.parse(producer.messages[3]?.value ?? ''));
    expect(event.detail).toMatchObject({ boundName: 'unmodeled_principal', principal: 'service' });
    expect(event.resourceId).toBe(realService);
  });

  it('the anomaly action is NEVER in its own counted set (the self-feeding rule)', async () => {
    // A second exceeded event in the chain (beyond the one case 2 ingested):
    // if the counted set admitted it, its detail has no field, so it would
    // surface as a missing_field/unknown_prefix breach on the next tick.
    const result = await ingestor.ingest(
      JSON.stringify(
        makeEvent({
          action: 'crypto.decrypt_rate.exceeded',
          actorType: 'system',
          actorId: null,
          resourceType: 'decrypt_rate',
          occurredAt: IN_WINDOW,
          detail: { boundName: 'doc_user', count: 501 },
        }),
      ),
    );
    expect(result).toMatchObject({ status: 'appended' });
    await detector.tick();
    expect(producer.messages).toHaveLength(4); // nothing new was counted
  });

  it('the window ages an episode out, and a fresh burst re-arms it', async () => {
    clockNow = new Date(NOW.getTime() + 600_000); // every event above leaves the window
    await detector.tick();
    expect(producer.messages).toHaveLength(4); // cleared, nothing emitted
    const again = new Date(clockNow.getTime() - 30_000).toISOString();
    for (let i = 0; i < mfaMax + 1; i++) {
      await ingestor.ingest(
        JSON.stringify(
          makeEvent({
            action: 'crypto.field.decrypted',
            actorType: 'user',
            actorId: burstUser,
            resourceType: 'field',
            occurredAt: again,
            detail: { dekId: randomUUID(), field: 'mfa_methods.totp_secret', purpose: 'int_probe' },
          }),
        ),
      );
    }
    await detector.tick();
    expect(producer.messages).toHaveLength(5); // the SAME principal, a NEW episode
    const event = AuditEventSchema.parse(JSON.parse(producer.messages[4]?.value ?? ''));
    expect(event.resourceId).toBe(burstUser);
  });

  it('the whole chain still verifies over everything this suite appended', async () => {
    await expect(verifier.verify()).resolves.toMatchObject({ ok: true });
  });
});
