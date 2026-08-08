import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { FieldCrypto, LocalKmsProvider } from '@estate/crypto';
import { NOTIFICATION_KINDS } from '@estate/notifications-client';
import { Migrator } from '@estate/db';
import { InMemoryAuditProducer } from '@estate/kafka';
import { Client } from 'pg';
import { Db } from '../src/db';
import { PgNotificationDekRepository } from '../src/dek.repository';
import { StubEmailSender } from '../src/email';
import { EventsService } from '../src/events.service';
import { NotificationsService } from '../src/notifications.service';
import { RecipientsRepo } from '../src/recipients.repo';
import { SendsRepo } from '../src/sends.repo';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

describeIfPg('notifications service against Postgres (core-cluster co-tenant)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `notificationssvc_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let service: NotificationsService;
  let stub: StubEmailSender;
  let producer: InMemoryAuditProducer;

  const OWNER = randomUUID();

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);

    const migrClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrClient.connect();
    try {
      await new Migrator(migrClient, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await migrClient.end();
    }

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    stub = new StubEmailSender();
    producer = new InMemoryAuditProducer();
    const events = new EventsService(producer, () => new Date());
    const crypto = new FieldCrypto(
      new LocalKmsProvider(Buffer.alloc(32, 7)),
      new PgNotificationDekRepository(db),
      async () => {
        // Decrypt-audit sink: the unit suite asserts its payload; here the
        // interesting property is that decryption WORKS against real rows.
      },
      { kekAlias: 'notifications/kek' },
    );
    service = new NotificationsService(
      db,
      new RecipientsRepo(db),
      new SendsRepo(db),
      events,
      crypto,
      stub,
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  it('stores the recipient as ciphertext under a notifications-kek DEK', async () => {
    await service.upsertRecipient({ userId: OWNER, email: 'owner@example.com' });

    const rows = await admin.query<{ email_ct: Buffer; dek_id: string }>(
      `SELECT email_ct, dek_id FROM ${schema}.notification_recipients WHERE user_id = $1`,
      [OWNER],
    );
    expect(rows.rows).toHaveLength(1);
    // Ciphertext, not plaintext, at rest.
    expect(rows.rows[0]?.email_ct.toString('utf8')).not.toContain('owner@example.com');
    const deks = await admin.query<{ kek_alias: string }>(
      `SELECT kek_alias FROM ${schema}.notification_deks WHERE user_id = $1 AND destroyed_at IS NULL`,
      [OWNER],
    );
    expect(deks.rows[0]?.kek_alias).toBe('notifications/kek');
  });

  it('round-trips: a send decrypts the stored address and reaches the carrier', async () => {
    const result = await service.send({
      userId: OWNER,
      kind: 'settlement.case_opened',
      channel: 'push',
      deadline: '2026-08-09T00:00:00.000Z',
    });

    expect(result).toEqual({ delivered: true, channel: 'email' });
    expect(stub.sent.at(-1)?.to).toBe('owner@example.com');
    const sends = await admin.query<{ outcome: string; requested_channel: string }>(
      `SELECT outcome, requested_channel FROM ${schema}.notification_sends WHERE user_id = $1`,
      [OWNER],
    );
    expect(sends.rows.at(-1)).toEqual({ outcome: 'sent', requested_channel: 'push' });
  });

  it('re-upsert replaces in place and the versions trigger captures the prior row', async () => {
    await service.upsertRecipient({ userId: OWNER, email: 'new-address@example.com' });

    const rows = await admin.query(
      `SELECT 1 FROM ${schema}.notification_recipients WHERE user_id = $1 AND deleted_at IS NULL`,
      [OWNER],
    );
    expect(rows.rowCount).toBe(1);
    const versions = await admin.query(
      `SELECT 1 FROM ${schema}.notification_recipients_versions WHERE row_id = $1`,
      [OWNER],
    );
    expect(versions.rowCount).toBeGreaterThanOrEqual(1);

    const result = await service.send({ userId: OWNER, kind: 'vault.reset', channel: 'email' });
    expect(result.delivered).toBe(true);
    expect(stub.sent.at(-1)?.to).toBe('new-address@example.com');
  });

  /**
   * THE CHECK MUST NEVER FALL BEHIND THE ENUM, and this is the test that says
   * so in a way nobody has to remember.
   *
   * `contact.link_claimed` was on the wire, in the template registry and in
   * profile's adapter from M13 while the DDL's kind CHECK still listed the nine
   * M9 kinds — so every real link claim mailed the owner and then threw on the
   * INSERT, which left no send row, no `notification.sent` event, and a
   * `contact.link.claimed` audit event asserting `ownerNotified: 'failed'`
   * about an owner who HAD been notified (migration 002 records the full
   * sequence). Nothing caught it because the unit suite fakes the repo and the
   * three kinds exercised here by hand were all M9 ones.
   *
   * DERIVED FROM `NOTIFICATION_KINDS`, never a list of its own: a hand-copied
   * list beside a thing that grows is exactly the drift class that produced the
   * defect, and docs/04 boundary rule 6 forbids it in a gate. Adding a kind
   * without widening the CHECK now turns this red on the first run.
   *
   * It asserts the ROW, not just the absence of a throw: a future `send` that
   * swallowed its own insert failure would still be caught.
   */
  it('records a row for every kind the wire enum declares', async () => {
    const subject = randomUUID();
    await service.upsertRecipient({ userId: subject, email: 'every-kind@example.com' });

    for (const kind of NOTIFICATION_KINDS) {
      const result = await service.send({ userId: subject, kind, channel: 'email' });
      expect(result).toEqual({ delivered: true, channel: 'email' });
    }

    const rows = await admin.query<{ kind: string }>(
      `SELECT kind FROM ${schema}.notification_sends WHERE user_id = $1 ORDER BY created_at`,
      [subject],
    );
    expect([...rows.rows.map((row) => row.kind)].sort()).toEqual([...NOTIFICATION_KINDS].sort());
  });

  it('records no_recipient for a user the store has never seen', async () => {
    const stranger = randomUUID();
    const result = await service.send({
      userId: stranger,
      kind: 'emergency.requested',
      channel: 'email',
    });

    expect(result).toEqual({ delivered: false, channel: 'email' });
    const sends = await admin.query<{ outcome: string }>(
      `SELECT outcome FROM ${schema}.notification_sends WHERE user_id = $1`,
      [stranger],
    );
    expect(sends.rows[0]?.outcome).toBe('no_recipient');
  });
});
