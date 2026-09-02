import { randomBytes, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { AuditEmitter } from '@estate/audit-emitter';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AuditEventSchema } from '@estate/contracts';
import { Client } from 'pg';
import { AuditIngestor } from '../src/ingestor';
import { ChainVerifier } from '../src/verifier';
import { DECRYPT_RATE_SQL, DecryptRateDetector } from '../src/decrypt-rate-detector';
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

  it('a legitimate amount reveal is SILENT, and the operator bound still breaches above it', async () => {
    // THE DEFECT THIS CASE USED TO ASSERT (M48 PR3). It read "one decrypt under
    // an encrypt-only prefix breaches immediately", and that was true and wrong
    // together: M23 PR4b shipped `distributionAmount` on 2026-08-21, so from
    // that day every dual-control amount check an operator performed fired the
    // loudest class in the table at count 1 — a reviewed path raising the alarm
    // reserved for unreviewed ones, which is how an alarm stops being read.
    //
    // BOTH HALVES, because either alone is satisfiable by a mistake — and the
    // mutations are NOT symmetric, which an earlier draft of this comment got
    // backwards by naming deletion for the first half. Deleting the row does
    // not give silence: `boundFor` falls through to `unmodeled_principal`/0 and
    // ONE decrypt breaches, which reddens the first half and passes the second.
    // Silence at one reveal alone is what a ceiling set absurdly high would
    // give, or a detector that never ticks; a breach above the ceiling alone is
    // what the old encrypt-only zero gave, since it fired at 1 as well as at 61.
    // So the two halves fail to different mutations, which is the point of
    // asserting both.
    const operator = randomUUID();
    const opMax = boundFor('distributions', 'operator').maxPerWindow;
    await ingestDecrypts(1, {
      field: 'distributions.amount',
      actorId: operator,
      actorType: 'operator',
    });
    await detector.tick();
    // Still two: the reveal an operator actually performs says nothing.
    expect(producer.messages).toHaveLength(2);

    await ingestDecrypts(opMax, {
      field: 'distributions.amount',
      actorId: operator,
      actorType: 'operator',
    });
    await detector.tick();
    expect(producer.messages).toHaveLength(3);
    const event = AuditEventSchema.parse(JSON.parse(producer.messages[2]?.value ?? ''));
    expect(event.detail).toMatchObject({
      boundName: 'distributions_operator',
      prefixClass: 'distributions',
      count: opMax + 1,
    });
    expect(event.resourceId).toBe(operator);
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

/**
 * The distinct-subject dimension against real Postgres.
 *
 * `count(DISTINCT CASE …)` is the one piece of this detector no unit test can
 * reach: the segment index lives in a SQL string, and whether Postgres pulls
 * out the subject the declaration names is a question only Postgres answers.
 * These cases run the EXPORTED constant rather than a copy, so the query under
 * test cannot drift from the query that ships.
 *
 * Its own schema and its own detector: the block above is one continuous
 * episode story whose message counts are load-bearing, and 1500-row bursts do
 * not belong inside it.
 */
describeIfPg('decrypt-rate distinct subjects (integration)', () => {
  const url = process.env['PG_TEST_URL'] ?? '';
  const schema = `audit_distinct_${randomBytes(4).toString('hex')}`;
  let admin: Client;
  let session: Client;
  let ingestor: AuditIngestor;
  let producer: InMemoryAuditProducer;
  let detector: DecryptRateDetector;

  const assetBound = boundFor('asset', 'user');
  const countMax = assetBound.maxPerWindow;
  const distinctMax = assetBound.maxDistinctSubjectsPerWindow as number;

  const browser = randomUUID();
  const harvester = randomUUID();

  beforeAll(async () => {
    admin = new Client({ connectionString: url });
    await admin.connect();
    await admin.query(`CREATE SCHEMA "${schema}"`);
    session = new Client({ connectionString: url, options: `-c search_path=${schema}` });
    await session.connect();
    await new Migrator(session, join(__dirname, '..', 'migrations')).migrate();
    ingestor = new AuditIngestor(session);
    producer = new InMemoryAuditProducer();
    detector = new DecryptRateDetector(session, new AuditEmitter(producer), () => NOW);
  });

  afterAll(async () => {
    await session.end();
    await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await admin.end();
  });

  /** `n` decrypts for `actorId`, cycling over `subjects` distinct asset ids. */
  async function ingestAssetReads(n: number, actorId: string, subjects: string[]): Promise<void> {
    for (let i = 0; i < n; i++) {
      const assetId = subjects[i % subjects.length] as string;
      const result = await ingestor.ingest(
        JSON.stringify(
          makeEvent({
            action: 'crypto.field.decrypted',
            actorType: 'user',
            actorId,
            resourceType: 'field',
            occurredAt: IN_WINDOW,
            detail: {
              dekId: randomUUID(),
              field: `asset.${assetId}.est_value`,
              purpose: 'int_probe',
            },
          }),
        ),
      );
      expect(result).toMatchObject({ status: 'appended' });
    }
  }

  const ids = (n: number): string[] => Array.from({ length: n }, () => randomUUID());

  it('the SQL extracts the DECLARED segment, and reports 0 for a prefix that declares none', async () => {
    const reader = randomUUID();
    const two = ids(2);
    await ingestAssetReads(6, reader, two);
    // A doc read by the same principal: `doc.<owner>.v1.<sha>` declares no
    // subject, so its CASE arm is NULL and count(DISTINCT) ignores it. If
    // someone declared `doc` at segment 2 (the tempting position — it holds a
    // UUID), this row would report 1 instead of 0 for four different
    // documents, which is the blind spot the declaration's docstring warns of.
    for (let i = 0; i < 4; i++) {
      await ingestor.ingest(
        JSON.stringify(
          makeEvent({
            action: 'crypto.field.decrypted',
            actorType: 'user',
            actorId: reader,
            resourceType: 'field',
            occurredAt: IN_WINDOW,
            detail: {
              dekId: randomUUID(),
              field: `doc.${reader}.v1.${randomBytes(8).toString('hex')}`,
              purpose: 'int_probe',
            },
          }),
        ),
      );
    }
    const since = new Date(NOW.getTime() - 300_000);
    const { rows } = await session.query<{
      prefix: string;
      actor_id: string;
      n: number;
      distinct_subjects: number;
    }>(DECRYPT_RATE_SQL, [since]);
    const mine = rows.filter((r) => r.actor_id === reader);
    expect(mine).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ prefix: 'asset', n: 6, distinct_subjects: 2 }),
        expect.objectContaining({ prefix: 'doc', n: 4, distinct_subjects: 0 }),
      ]),
    );
  });

  it('a large estate read repeatedly is SILENT — high count, bounded subjects', async () => {
    // The measured false positive, reproduced at the real bound against the
    // real index: over the count bound by a wide margin, well under the
    // distinct bound, because re-reading a row you already read moves no
    // plaintext you had not already seen.
    await ingestAssetReads(countMax + 200, browser, ids(120));
    await detector.tick();
    expect(producer.messages).toHaveLength(0);
  });

  it('a mass read of DIFFERENT assets breaches — the positive control', async () => {
    await ingestAssetReads(distinctMax + 1, harvester, ids(distinctMax + 1));
    await detector.tick();
    expect(producer.messages).toHaveLength(1);
    const event = AuditEventSchema.parse(JSON.parse(producer.messages[0]?.value ?? ''));
    expect(event.resourceId).toBe(harvester);
    expect(event.detail).toMatchObject({
      boundName: 'asset_user',
      prefixClass: 'asset',
      count: distinctMax + 1,
      distinctSubjects: distinctMax + 1,
      distinctBound: distinctMax,
    });
    // And the browser, still over the count bound in the same window, is
    // still silent — the two principals are evaluated on the same tick, so
    // this is one detector telling them apart rather than two runs.
    expect(producer.messages).toHaveLength(1);
  });
});
