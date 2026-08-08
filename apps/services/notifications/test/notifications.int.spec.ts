import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { FieldCrypto, LocalKmsProvider } from '@estate/crypto';
import { ESTATE_NOTIFICATION_KINDS, NOTIFICATION_KINDS } from '@estate/notifications-client';
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
      () => new Date(),
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

    // M14: this owner has not proved their address yet, so the delivery is
    // recorded as `sent_unverified`. `delivered` stays true — the carrier took
    // it — and the same owner's `sent` case is covered once they verify below.
    expect(result).toEqual({ delivered: true, channel: 'email', recipientVerified: false });
    expect(stub.sent.at(-1)?.to).toBe('owner@example.com');
    const sends = await admin.query<{ outcome: string; requested_channel: string }>(
      `SELECT outcome, requested_channel FROM ${schema}.notification_sends WHERE user_id = $1`,
      [OWNER],
    );
    expect(sends.rows.at(-1)).toEqual({ outcome: 'sent_unverified', requested_channel: 'push' });
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

    for (const kind of ESTATE_NOTIFICATION_KINDS) {
      const result = await service.send({ userId: subject, kind, channel: 'email' });
      expect(result).toMatchObject({ delivered: true, channel: 'email' });
    }
    // The system kinds are unreachable through `send` BY DESIGN (their
    // templates need a code), so each has its own entry point — and the
    // assertion below is over NOTIFICATION_KINDS, so a system kind added
    // without a route here fails rather than quietly going unlogged.
    expect(
      await service.sendAddressVerification({ userId: subject, code: 'EV1-TEST' }),
    ).toMatchObject({ delivered: true, channel: 'email' });

    const rows = await admin.query<{ kind: string }>(
      `SELECT kind FROM ${schema}.notification_sends WHERE user_id = $1 ORDER BY created_at`,
      [subject],
    );
    expect([...rows.rows.map((row) => row.kind)].sort()).toEqual([...NOTIFICATION_KINDS].sort());
  });

  /**
   * M14. The four properties migration 003 CLAIMS, asserted against a real
   * database rather than assumed — two of them are "free" consequences of
   * existing machinery, which is exactly the kind of claim that turns out to be
   * wrong (the M13 lesson: a fix whose behaviour lives in SQL must be pinned by
   * a test that runs SQL).
   */
  describe('the verified bit', () => {
    const SUBJECT = randomUUID();

    it('starts unverified, and a mark makes it verified', async () => {
      await service.upsertRecipient({ userId: SUBJECT, email: 'proof@example.com' });
      expect(await service.recipientStatus(SUBJECT)).toEqual({ verified: false });

      expect(await service.markRecipientVerified(SUBJECT)).toEqual({ ok: true });
      expect(await service.recipientStatus(SUBJECT)).toEqual({ verified: true });
    });

    it('is NEVER re-stamped, so it answers when an address was FIRST proved', async () => {
      const [before] = await admin
        .query<{ verified_at: Date }>(
          `SELECT verified_at FROM ${schema}.notification_recipients WHERE user_id = $1`,
          [SUBJECT],
        )
        .then((r) => r.rows);
      await service.markRecipientVerified(SUBJECT);
      const [after] = await admin
        .query<{ verified_at: Date }>(
          `SELECT verified_at FROM ${schema}.notification_recipients WHERE user_id = $1`,
          [SUBJECT],
        )
        .then((r) => r.rows);
      expect(after?.verified_at.toISOString()).toBe(before?.verified_at.toISOString());
    });

    it('SURVIVES the login re-feed — otherwise no address could ever stay verified', async () => {
      // Identity re-feeds this store on EVERY login. The address it carries is
      // by construction the one already on file (login resolves the user by
      // email_bidx first), which is what makes preserving the bit sound.
      await service.upsertRecipient({ userId: SUBJECT, email: 'proof@example.com' });
      expect(await service.recipientStatus(SUBJECT)).toEqual({ verified: true });
    });

    it("records plain `sent` once proved — the send log's own evidence (M14)", async () => {
      const result = await service.send({
        userId: SUBJECT,
        kind: 'vault.reset',
        channel: 'email',
      });
      expect(result).toMatchObject({ delivered: true, recipientVerified: true });
      const { rows } = await admin.query<{ outcome: string }>(
        `SELECT outcome FROM ${schema}.notification_sends
          WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`,
        [SUBJECT],
      );
      expect(rows[0]?.outcome).toBe('sent');
    });

    it('is CAPTURED by the versions trigger with no trigger change', async () => {
      // Free because the trigger stores a whole-row `to_jsonb(OLD)` image —
      // claimed by migration 003, so proved here rather than believed.
      const { rows } = await admin.query<{ row_data: { verified_at: string | null } }>(
        `SELECT row_data FROM ${schema}.notification_recipients_versions
          WHERE row_id = $1 ORDER BY version_seq DESC LIMIT 1`,
        [SUBJECT],
      );
      expect(rows[0]?.row_data).toHaveProperty('verified_at');
      expect(rows[0]?.row_data.verified_at).not.toBeNull();
    });

    it('DIES WITH THE ROW: a soft-deleted recipient is unverified again', async () => {
      // The arming gates then refuse, fail-closed by construction rather than
      // by a separate check — a crypto-shredded or deleted recipient must not
      // keep vouching for an address the store can no longer reach.
      const doomed = randomUUID();
      await service.upsertRecipient({ userId: doomed, email: 'doomed@example.com' });
      await service.markRecipientVerified(doomed);
      expect(await service.recipientStatus(doomed)).toEqual({ verified: true });

      // THROUGH `db`, NOT `admin`, and the reason is a real defect this test
      // had on its first run. The soft delete fires the version-capture
      // trigger, whose INSERT names `notification_recipients_versions`
      // UNQUALIFIED — so it resolves on the EXECUTING CONNECTION's search_path,
      // not on the schema the UPDATE was qualified with. `admin` has no
      // scratch-schema search_path, so on a developer machine whose PG_TEST_URL
      // points at the running stack's core cluster the trigger found the
      // stack's own `public.notification_recipients_versions` and the test
      // passed WHILE WRITING A ROW INTO THE LIVE STACK. CI has no such table
      // and the same statement failed there. `db` carries
      // `-c search_path=<schema>`, which every other write here already uses.
      await db.query(`UPDATE notification_recipients SET deleted_at = now() WHERE user_id = $1`, [
        doomed,
      ]);
      // The capture landed in the SCRATCH schema — asserted, so the mistake
      // above cannot recur silently in either direction. The NEWEST version row
      // is the soft delete's PRE-image, so it still shows a live, verified row:
      // that is what identifies this capture as the soft delete's rather than
      // the mark-verified UPDATE's, which the trigger also recorded.
      const { rows: captured } = await admin.query<{
        row_data: { deleted_at: string | null; verified_at: string | null };
      }>(
        `SELECT row_data FROM ${schema}.notification_recipients_versions
          WHERE row_id = $1 AND operation = 'UPDATE'
          ORDER BY version_seq DESC LIMIT 1`,
        [doomed],
      );
      expect(captured[0]?.row_data.deleted_at).toBeNull();
      expect(captured[0]?.row_data.verified_at).not.toBeNull();

      expect(await service.recipientStatus(doomed)).toEqual({ verified: false });
      // And it cannot be vouched for again while deleted.
      expect(await service.markRecipientVerified(doomed)).toEqual({ ok: false });
    });

    it('DIES WITH THE DEK TOO: a crypto-shredded recipient stops vouching', async () => {
      // The half migration 003 asserted and nobody tested — found false by the
      // M14 review. Crypto-shredding destroys the DEK, NOT the row, so before
      // the fix `findStatus` still answered `verified: true` for an address the
      // service could no longer decrypt: the arming gates would ARM while every
      // subsequent alert recorded `carrier_failure`. Exactly the fail-open M14
      // exists to remove, inside the machinery that removes it.
      //
      // The soft-delete case above and this one are the TWO halves of that
      // claim; only one of them used to exist, and the comment named both.
      const shredded = randomUUID();
      await service.upsertRecipient({ userId: shredded, email: 'shredded@example.com' });
      await service.markRecipientVerified(shredded);
      expect(await service.recipientStatus(shredded)).toEqual({ verified: true });

      // Shred: the DEK goes, the row stays — which is the whole point of
      // crypto-shredding as this platform defines it.
      await admin.query(
        `UPDATE ${schema}.notification_deks SET destroyed_at = now() WHERE user_id = $1`,
        [shredded],
      );
      const { rows } = await admin.query(
        `SELECT 1 FROM ${schema}.notification_recipients
          WHERE user_id = $1 AND deleted_at IS NULL AND verified_at IS NOT NULL`,
        [shredded],
      );
      expect(rows).toHaveLength(1); // the row really is still live and still stamped

      expect(await service.recipientStatus(shredded)).toEqual({ verified: false });
      // ...and the WRITE agrees with the read. Round 2 of the M14 review found
      // the first fix put the DEK predicate only on `findStatus`, so this still
      // returned true and stamped the row: the platform would tell a user their
      // address was verified in the same breath as telling every gate it was
      // not.
      expect(await service.markRecipientVerified(shredded)).toEqual({ ok: false });

      // AND THE SHRED SURVIVES THE NEXT LOGIN. Identity re-feeds this store on
      // every login, `encryptField` mints a fresh DEK once the old one is
      // destroyed, and the upsert used to preserve `verified_at` — so the row
      // came back with an active key and an untouched proof, and every arming
      // gate re-armed with nothing re-proved. A change of key clears the proof.
      await service.upsertRecipient({ userId: shredded, email: 'shredded@example.com' });
      expect(await service.recipientStatus(shredded)).toEqual({ verified: false });
    });

    it('answers false — never throws — for a user the store has never seen', async () => {
      expect(await service.recipientStatus(randomUUID())).toEqual({ verified: false });
      expect(await service.markRecipientVerified(randomUUID())).toEqual({ ok: false });
    });
  });

  it('records no_recipient for a user the store has never seen', async () => {
    const stranger = randomUUID();
    const result = await service.send({
      userId: stranger,
      kind: 'emergency.requested',
      channel: 'email',
    });

    expect(result).toEqual({ delivered: false, channel: 'email', recipientVerified: false });
    const sends = await admin.query<{ outcome: string }>(
      `SELECT outcome FROM ${schema}.notification_sends WHERE user_id = $1`,
      [stranger],
    );
    expect(sends.rows[0]?.outcome).toBe('no_recipient');
  });
});
