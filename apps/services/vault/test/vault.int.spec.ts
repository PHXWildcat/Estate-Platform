/**
 * End-to-end integration test against a real Postgres, gated exactly like
 * packages/db: set PG_TEST_URL to run (CI service container). Runs the
 * service's real migrations into a scratch schema, boots the Nest app over it,
 * and drives the whole vault with supertest using the REAL client crypto from
 * @estate/vault-crypto - so the SRP handshake, the key derivation and the item
 * envelopes in these tests are the ones a browser would produce.
 *
 * The assertions worth reading are the ones about what is NOT there: the vault
 * password never reaches the server, the database holds nothing but ciphertext,
 * and every audit payload is free of vault content.
 */
import 'reflect-metadata';
import type { Server } from 'node:http';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import { checkConventions, Migrator } from '@estate/db';
import { AuditEventSchema, TOPICS, type MfaLevel } from '@estate/contracts';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import {
  buildKeysetChange,
  createVaultEnrollment,
  decryptItem,
  encryptItem,
  exportMasterKeyBytes,
  finishUnlock,
  MIN_ITERATIONS,
  prepareUnlock,
  proveUnlock,
  utf8,
  type VaultKeysetPayload,
} from '@estate/vault-crypto';
import { Client } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AUDIT_PRODUCER, NOTIFIER, PG_POOL_CONFIG } from '../src/di-tokens';
import type { NotificationPort, NotifyOutcome } from '../src/notifications';
import { VAULT_SESSION_HEADER } from '../src/vault-session.guard';
import type {
  KeysetStatus,
  SrpChallenge,
  VaultItemDto,
  VaultItemPage,
  VaultOpened,
  VaultVersionDto,
} from '../src/vault.service';

/**
 * A notifier shaped like every PRODUCTION adapter since M14: it never throws,
 * it reports what happened. The default stub reports delivered, which is why it
 * could not catch the regression `reset` shipped with — see the reset spec.
 */
const notifierOutcome: { delivered: boolean; recipientVerified: boolean } = {
  delivered: false,
  recipientVerified: false,
};
const failingNotifier: NotificationPort = {
  channel: 'email',
  deliversToRealChannels: true,
  recipientVerified: (): Promise<boolean> => Promise.resolve(false),
  notify: (): Promise<NotifyOutcome> => Promise.resolve({ ...notifierOutcome }),
};

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const OWNER = randomUUID();
const STRANGER = randomUUID();
const VAULT_PASSWORD = 'correct horse battery staple';
const ITEM_SECRET = 'bank.example.com / alexandra / hunter2-and-then-some';
const ACCOUNT_SESSION = '00000000-0000-4000-8000-000000000000';
const OTHER_ACCOUNT_SESSION = '11111111-1111-4111-8111-111111111111';

/**
 * Stands in for real identity introspection: a bearer token of the form
 * `<level>:<userId>` verifies to that session. `<level>:<userId>:<sessionId>`
 * pins a specific account session, which the vault-session binding needs. The
 * real cross-service path is proven in the vault e2e.
 */
const fakeVerifier: SessionVerifier = {
  verify: (token) => {
    const m = /^(mfa|stepup):([0-9a-f-]{36})(?::([0-9a-f-]{36}))?$/.exec(token);
    if (!m) return Promise.resolve(null);
    const [, level, userId, sessionId] = m;
    const ctx: SessionContext = {
      userId: userId!,
      sessionId: sessionId ?? ACCOUNT_SESSION,
      mfaLevel: level as MfaLevel,
      audience: 'account',
      stepupExpiresAt: level === 'stepup' ? new Date(Date.now() + 5 * 60 * 1000) : null,
    };
    return Promise.resolve(ctx);
  },
};

const bearer = (
  level: 'mfa' | 'stepup',
  userId: string,
  sessionId?: string,
): Record<string, string> => ({
  authorization: `Bearer ${level}:${userId}${sessionId ? `:${sessionId}` : ''}`,
});

describeIfPg('vault service end to end', () => {
  jest.setTimeout(180_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `vaultsvc_test_${Date.now()}`;
  let admin: Client;
  let app: INestApplication;
  let server: Server;
  let producer: InMemoryAuditProducer;

  let enrollment: VaultKeysetPayload;
  let secretKey: string;

  const asOwner = (): Record<string, string> => bearer('mfa', OWNER);
  const withStepUp = (): Record<string, string> => bearer('stepup', OWNER);

  /** Complete an SRP unlock the way a client does, end to end. */
  async function openVault(
    password = VAULT_PASSWORD,
    key = secretKey,
    headers: Record<string, string> = withStepUp(),
  ): Promise<{ token: string; masterKey: CryptoKey; keysetAuthKey: Uint8Array }> {
    const challenge = await request(server)
      .post('/v1/vault/srp/start')
      .set(headers)
      .expect(201)
      .then((res) => res.body as SrpChallenge);

    const preparation = await prepareUnlock({
      userId: OWNER,
      password,
      secretKey: key,
      kdfParams: challenge.kdfParams,
      srpSalt: challenge.srpSalt,
    });
    const { m1, session } = await proveUnlock(preparation, challenge.serverPublic);

    const opened = await request(server)
      .post('/v1/vault/srp/verify')
      .set(headers)
      .send({
        handshakeId: challenge.handshakeId,
        clientPublic: preparation.publicA,
        clientProof: m1,
      })
      .expect(200)
      .then((res) => res.body as VaultOpened);

    const unlocked = await finishUnlock({
      preparation,
      session,
      serverM2: opened.serverProof,
      wrappedMasterKey: opened.wrappedMasterKey,
      vaultSessionId: opened.vaultSession.id,
    });
    return { token: opened.vaultSession.token, ...unlocked };
  }

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.query(`SET search_path TO ${schema}, public`);

    const migrationClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrationClient.connect();
    try {
      const { applied } = await new Migrator(
        migrationClient,
        `${__dirname}/../migrations`,
      ).migrate();
      expect(applied).toContain('001_vault_schema.sql');
    } finally {
      await migrationClient.end();
    }

    process.env['DATABASE_URL'] = pgUrl;
    delete process.env['KAFKA_BROKERS'];
    process.env['NODE_ENV'] = 'test';

    producer = new InMemoryAuditProducer();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AUDIT_PRODUCER)
      .useValue(producer)
      .overrideProvider(PG_POOL_CONFIG)
      .useValue({ connectionString: pgUrl, options: `-c search_path=${schema}` })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(fakeVerifier)
      // A notifier that REPORTS NON-DELIVERY without throwing — the shape every
      // production adapter has since M14 turned the port outcome-based. The
      // default stub reports delivered, so it could never have caught the
      // regression below.
      .overrideProvider(NOTIFIER)
      .useValue(failingNotifier)
      .compile();

    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    server = app.getHttpServer() as Server;

    const created = await createVaultEnrollment({
      userId: OWNER,
      password: VAULT_PASSWORD,
      iterations: MIN_ITERATIONS,
    });
    enrollment = created.enrollment.payload;
    secretKey = created.enrollment.secretKey;
  });

  afterAll(async () => {
    if (app) await app.close();
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  it('the migrated vault schema satisfies the docs/02 conventions', async () => {
    const violations = await checkConventions(admin, {
      schema,
      businessTables: ['vault_items'],
      appendOnlyTables: ['vault_items_versions', 'vault_keysets_versions'],
    });
    expect(violations).toEqual([]);
  });

  it('versions vault_keysets on its own primary key, like profiles', async () => {
    // Qualified by schema, not just table name. Every suite in this repo runs
    // in its own scratch schema inside ONE database, so an unqualified
    // pg_catalog query sees every other suite's identically-named tables too -
    // which made this assertion pass or fail purely on jest's file ordering.
    const triggers = await admin.query<{ tgname: string }>(
      `SELECT t.tgname FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relname = 'vault_keysets' AND NOT t.tgisinternal`,
      [schema],
    );
    expect(triggers.rows.map((r) => r.tgname).sort()).toEqual([
      'trg_vault_keysets_updated_at',
      'trg_vault_keysets_versions',
    ]);
  });

  describe('enrollment', () => {
    it('reports an unenrolled vault before anything exists', async () => {
      const res = await request(server).get('/v1/vault/keyset').set(asOwner()).expect(200);
      expect(res.body).toEqual({ enrolled: false, updatedAt: null });
    });

    it('refuses to enroll without a fresh step-up', async () => {
      await request(server)
        .post('/v1/vault/keyset')
        .set(asOwner())
        .send(enrollment)
        .expect(403, { error: 'stepup_required' });
    });

    it('refuses an unauthenticated caller', async () => {
      await request(server)
        .post('/v1/vault/keyset')
        .send(enrollment)
        .expect(401, { error: 'unauthorized' });
    });

    it('enrolls under step-up', async () => {
      const res = await request(server)
        .post('/v1/vault/keyset')
        .set(withStepUp())
        .send(enrollment)
        .expect(201);
      expect((res.body as KeysetStatus).enrolled).toBe(true);
    });

    it('refuses to overwrite an existing keyset', async () => {
      await request(server)
        .post('/v1/vault/keyset')
        .set(withStepUp())
        .send(enrollment)
        .expect(409, { error: 'keyset_exists' });
    });

    it('stores the verifier and wrapped key as opaque bytes, and no password', async () => {
      const rows = await admin.query<{
        srp_verifier: Buffer;
        wrapped_master_key: Buffer;
        kdf_params: { iterations: number };
      }>(
        `SELECT srp_verifier, wrapped_master_key, kdf_params FROM vault_keysets WHERE user_id = $1`,
        [OWNER],
      );
      const row = rows.rows[0]!;
      expect(row.srp_verifier).toHaveLength(512);
      expect(row.kdf_params.iterations).toBe(MIN_ITERATIONS);

      // Nothing derived from the password or the Secret Key is recoverable.
      const stored = Buffer.concat([row.srp_verifier, row.wrapped_master_key]).toString('binary');
      expect(stored).not.toContain(VAULT_PASSWORD);
      expect(stored).not.toContain(secretKey);
    });
  });

  describe('unlock', () => {
    it('refuses to start a handshake without step-up', async () => {
      await request(server)
        .post('/v1/vault/srp/start')
        .set(asOwner())
        .expect(403, { error: 'stepup_required' });
    });

    it('opens the vault with the right password and Secret Key', async () => {
      const { token, masterKey } = await openVault();
      expect(token).toBeTruthy();
      expect(masterKey).toBeTruthy();
    });

    it('rejects the wrong vault password with a generic failure', async () => {
      const challenge = await request(server)
        .post('/v1/vault/srp/start')
        .set(withStepUp())
        .expect(201)
        .then((res) => res.body as SrpChallenge);

      const preparation = await prepareUnlock({
        userId: OWNER,
        password: 'not the vault password',
        secretKey,
        kdfParams: challenge.kdfParams,
        srpSalt: challenge.srpSalt,
      });
      const { m1 } = await proveUnlock(preparation, challenge.serverPublic);

      await request(server)
        .post('/v1/vault/srp/verify')
        .set(withStepUp())
        .send({
          handshakeId: challenge.handshakeId,
          clientPublic: preparation.publicA,
          clientProof: m1,
        })
        .expect(401, { error: 'srp_failed' });
    });

    it('burns the handshake on a failed attempt, so guesses cannot be ground', async () => {
      const challenge = await request(server)
        .post('/v1/vault/srp/start')
        .set(withStepUp())
        .expect(201)
        .then((res) => res.body as SrpChallenge);

      const wrong = await prepareUnlock({
        userId: OWNER,
        password: 'wrong once',
        secretKey,
        kdfParams: challenge.kdfParams,
        srpSalt: challenge.srpSalt,
      });
      const first = await proveUnlock(wrong, challenge.serverPublic);
      await request(server)
        .post('/v1/vault/srp/verify')
        .set(withStepUp())
        .send({
          handshakeId: challenge.handshakeId,
          clientPublic: wrong.publicA,
          clientProof: first.m1,
        })
        .expect(401);

      // Even the CORRECT proof is refused against a spent handshake.
      const right = await prepareUnlock({
        userId: OWNER,
        password: VAULT_PASSWORD,
        secretKey,
        kdfParams: challenge.kdfParams,
        srpSalt: challenge.srpSalt,
      });
      const second = await proveUnlock(right, challenge.serverPublic);
      await request(server)
        .post('/v1/vault/srp/verify')
        .set(withStepUp())
        .send({
          handshakeId: challenge.handshakeId,
          clientPublic: right.publicA,
          clientProof: second.m1,
        })
        .expect(401, { error: 'srp_failed' });
    });

    it('reports a missing keyset the same way to a stranger', async () => {
      await request(server)
        .post('/v1/vault/srp/start')
        .set(bearer('stepup', STRANGER))
        .expect(404, { error: 'keyset_not_found' });
    });
  });

  describe('items', () => {
    let vaultToken: string;
    let masterKey: CryptoKey;
    const itemId = randomUUID();

    beforeAll(async () => {
      const opened = await openVault();
      vaultToken = opened.token;
      masterKey = opened.masterKey;
    });

    const unlocked = (): Record<string, string> => ({
      ...asOwner(),
      [VAULT_SESSION_HEADER]: vaultToken,
    });

    it('refuses item access without an open vault', async () => {
      await request(server)
        .get('/v1/vault/items')
        .set(asOwner())
        .expect(403, { error: 'vault_locked' });
    });

    it('stores an encrypted item', async () => {
      const blob = await encryptItem(
        masterKey,
        { userId: OWNER, itemId, blobVersion: 1 },
        utf8(ITEM_SECRET),
      );
      const res = await request(server)
        .post('/v1/vault/items')
        .set(unlocked())
        .send({
          id: itemId,
          itemType: 'password',
          blob: Buffer.from(blob).toString('base64'),
        })
        .expect(201);

      const dto = res.body as VaultItemDto;
      expect(dto).toMatchObject({ id: itemId, itemType: 'password', blobVersion: 1 });
    });

    it('is idempotent when a create is retried', async () => {
      const blob = await encryptItem(
        masterKey,
        { userId: OWNER, itemId, blobVersion: 1 },
        utf8(ITEM_SECRET),
      );
      await request(server)
        .post('/v1/vault/items')
        .set(unlocked())
        .send({ id: itemId, itemType: 'password', blob: Buffer.from(blob).toString('base64') })
        .expect(409, { error: 'item_exists' });
    });

    it('round-trips the secret through the client', async () => {
      const res = await request(server)
        .get(`/v1/vault/items/${itemId}`)
        .set(unlocked())
        .expect(200);
      const dto = res.body as VaultItemDto;

      const plaintext = await decryptItem(
        masterKey,
        { userId: OWNER, itemId, blobVersion: dto.blobVersion },
        new Uint8Array(Buffer.from(dto.blob, 'base64')),
      );
      expect(Buffer.from(plaintext).toString('utf8')).toBe(ITEM_SECRET);
    });

    it('never stores the plaintext anywhere', async () => {
      const rows = await admin.query<{ blob_ct: Buffer }>(`SELECT blob_ct FROM vault_items`);
      for (const row of rows.rows) {
        expect(row.blob_ct.toString('binary')).not.toContain(ITEM_SECRET);
        expect(row.blob_ct.toString('binary')).not.toContain('bank.example.com');
      }
    });

    it('lists items for the owner', async () => {
      const res = await request(server).get('/v1/vault/items').set(unlocked()).expect(200);
      expect((res.body as { items: VaultItemDto[] }).items).toHaveLength(1);
    });

    it('updates under If-Match and bumps the blob version', async () => {
      const blob = await encryptItem(
        masterKey,
        { userId: OWNER, itemId, blobVersion: 2 },
        utf8('rotated secret'),
      );
      const res = await request(server)
        .put(`/v1/vault/items/${itemId}`)
        .set({ ...unlocked(), 'if-match': '1' })
        .send({ itemType: 'password', blob: Buffer.from(blob).toString('base64') })
        .expect(200);

      const dto = res.body as VaultItemDto;
      expect(dto.blobVersion).toBe(2);
      // The freshly written blob decrypts at exactly the version the server stored.
      const plaintext = await decryptItem(
        masterKey,
        { userId: OWNER, itemId, blobVersion: dto.blobVersion },
        new Uint8Array(Buffer.from(dto.blob, 'base64')),
      );
      expect(Buffer.from(plaintext).toString('utf8')).toBe('rotated secret');
    });

    it('rejects a stale If-Match', async () => {
      const blob = await encryptItem(
        masterKey,
        { userId: OWNER, itemId, blobVersion: 2 },
        utf8('conflicting'),
      );
      await request(server)
        .put(`/v1/vault/items/${itemId}`)
        .set({ ...unlocked(), 'if-match': '1' })
        .send({ itemType: 'password', blob: Buffer.from(blob).toString('base64') })
        .expect(409, { error: 'version_conflict' });
    });

    it('requires If-Match at all', async () => {
      await request(server)
        .put(`/v1/vault/items/${itemId}`)
        .set(unlocked())
        .send({ itemType: 'password', blob: Buffer.alloc(64).toString('base64') })
        .expect(400, { error: 'invalid_request' });
    });

    /*
     * THE ARM WHERE THE TWO NUMBERS DISAGREE (M27 PR1a).
     *
     * Every test above it is blind to this change, and that is the point of
     * writing it. On a row that has only ever been created and updated,
     * `blob_version` and `revision` advance together and are always EQUAL — so
     * an assertion driven through those states passes identically whether the
     * service compares `If-Match` to one or to the other. The behaviour only
     * becomes falsifiable once a row exists where they differ, which is exactly
     * the state M27's version restore creates.
     *
     * The divergence is forced here with SQL rather than waited for, because
     * PR1a ships the token and PR1b ships the restore that moves it: a change
     * whose proof arrives a PR later is a change nobody checked.
     */
    it('compares If-Match to the REVISION, not to the blob version', async () => {
      // Move blob_version somewhere revision is not. `vault_items` constrains
      // it only to be positive, which is what lets a restore put a captured
      // version back; the trigger advances revision on this write regardless.
      await admin.query(`UPDATE vault_items SET blob_version = 9 WHERE id = $1`, [itemId]);
      const state = await admin.query<{ blob_version: number; revision: number }>(
        `SELECT blob_version, revision FROM vault_items WHERE id = $1`,
        [itemId],
      );
      const { blob_version: blobVersion, revision } = state.rows[0]!;
      // ANTI-VACUITY: if these were equal the rest of this test would pass for
      // the wrong reason, which is the failure mode it exists to rule out.
      expect(blobVersion).toBe(9);
      expect(revision).not.toBe(blobVersion);

      // The BLOB VERSION is refused as a concurrency token...
      await request(server)
        .put(`/v1/vault/items/${itemId}`)
        .set({ ...unlocked(), 'if-match': String(blobVersion) })
        .send({ itemType: 'password', blob: Buffer.alloc(64).toString('base64') })
        .expect(409, { error: 'version_conflict' });

      // ...and the REVISION is accepted. The blob is sealed against
      // `blobVersion + 1` because that is what the service will store — the two
      // numbers are used for two different things in this one request.
      const blob = await encryptItem(
        masterKey,
        { userId: OWNER, itemId, blobVersion: blobVersion + 1 },
        utf8('written against the revision'),
      );
      const res = await request(server)
        .put(`/v1/vault/items/${itemId}`)
        .set({ ...unlocked(), 'if-match': String(revision) })
        .send({ itemType: 'password', blob: Buffer.from(blob).toString('base64') })
        .expect(200);

      const dto = res.body as VaultItemDto & { revision: number };
      expect(dto.blobVersion).toBe(blobVersion + 1);
      expect(dto.revision).toBe(revision + 1);
      // And it still opens, which is the half the AAD binding is responsible for.
      const plaintext = await decryptItem(
        masterKey,
        { userId: OWNER, itemId, blobVersion: dto.blobVersion },
        new Uint8Array(Buffer.from(dto.blob, 'base64')),
      );
      expect(Buffer.from(plaintext).toString('utf8')).toBe('written against the revision');
    });

    it('will not let a writer choose its own revision', async () => {
      const before = await admin.query<{ revision: number }>(
        `SELECT revision FROM vault_items WHERE id = $1`,
        [itemId],
      );
      // A statement that sets `revision` explicitly — the shape a future writer
      // would reach for, and the shape that would let a restore reuse a token.
      await admin.query(`UPDATE vault_items SET revision = 1 WHERE id = $1`, [itemId]);
      const after = await admin.query<{ revision: number }>(
        `SELECT revision FROM vault_items WHERE id = $1`,
        [itemId],
      );
      // The trigger overrode it. Not "rejected the statement" — assigned the
      // successor, so no caller has to remember and no caller can lie.
      expect(after.rows[0]!.revision).toBe(before.rows[0]!.revision + 1);
    });

    it('captures a version row attributed to the actor on update', async () => {
      // ORDERED, because `rows[0]` of an unordered scan is whatever Postgres
      // felt like returning — and this row is no longer the only one for this
      // item now that the revision tests write to it. The keyset history query
      // below has always ordered by `version_seq`; this one had not, so the two
      // spellings of one question disagreed about whether order mattered.
      const rows = await admin.query<{ actor_id: string; operation: string }>(
        `SELECT actor_id, operation FROM vault_items_versions
          WHERE row_id = $1 ORDER BY version_seq`,
        [itemId],
      );
      expect(rows.rows.length).toBeGreaterThan(0);
      expect(rows.rows[0]).toMatchObject({ actor_id: OWNER, operation: 'UPDATE' });
    });

    it("refuses a stranger's vault session", async () => {
      await request(server)
        .get(`/v1/vault/items/${itemId}`)
        .set({ ...bearer('mfa', STRANGER), [VAULT_SESSION_HEADER]: vaultToken })
        .expect(403, { error: 'vault_locked' });
    });

    it('refuses a vault session presented from a different account session', async () => {
      await request(server)
        .get(`/v1/vault/items/${itemId}`)
        .set({
          ...bearer('mfa', OWNER, OTHER_ACCOUNT_SESSION),
          [VAULT_SESSION_HEADER]: vaultToken,
        })
        .expect(403, { error: 'vault_locked' });
    });

    it('404s an unknown item', async () => {
      await request(server)
        .get(`/v1/vault/items/${randomUUID()}`)
        .set(unlocked())
        .expect(404, { error: 'not_found' });
    });

    /*
     * ONE REFUSAL FOR "NO SUCH ITEM" AND "NOT YOUR ITEM" (M27 PR1a).
     *
     * Before this, every item route read the row by id ALONE and then asked
     * Cedar, which answers `403 forbidden` — so a missing item gave 404 and
     * somebody else's gave 403, and the pair is an existence oracle for any
     * item UUID that leaks. docs/03's rule is a uniform 404 for both, and
     * CLAUDE.md's is that a read placed before the authz gate has already
     * answered a question about someone else's data.
     *
     * The fix is a fused predicate — `WHERE id = $1 AND user_id = $2` — so the
     * row never arrives to be refused distinguishably. This test compares the
     * two responses as WHOLE VALUES rather than asserting 404 twice: a status
     * match with a different body would still be a discriminator.
     */
    it('answers a stranger-owned item exactly as it answers a missing one', async () => {
      const strangersItem = randomUUID();
      await admin.query(
        `INSERT INTO vault_items (id, user_id, item_type, blob_ct, blob_version)
         VALUES ($1, $2, 'password', $3, 1)`,
        [strangersItem, STRANGER, Buffer.alloc(64, 7)],
      );
      // ANTI-VACUITY: the row has to actually exist, or both arms are the
      // missing-row arm and the test compares a thing to itself.
      const exists = await admin.query<{ n: string }>(
        `SELECT count(*) AS n FROM vault_items WHERE id = $1 AND user_id = $2`,
        [strangersItem, STRANGER],
      );
      expect(exists.rows[0]!.n).toBe('1');

      const absent = randomUUID();
      const probes: readonly { name: string; key: string; run: (id: string) => request.Test }[] = [
        {
          name: 'GET',
          key: "get('vault/items/:itemId')",
          run: (id) => request(server).get(`/v1/vault/items/${id}`).set(unlocked()),
        },
        {
          name: 'PUT',
          key: "put('vault/items/:itemId')",
          run: (id) =>
            request(server)
              .put(`/v1/vault/items/${id}`)
              .set({ ...unlocked(), 'if-match': '1' })
              .send({ itemType: 'password', blob: Buffer.alloc(64).toString('base64') }),
        },
        {
          name: 'DELETE',
          key: "delete('vault/items/:itemId')",
          run: (id) =>
            request(server)
              .delete(`/v1/vault/items/${id}`)
              .set({ ...withStepUp(), [VAULT_SESSION_HEADER]: vaultToken }),
        },
        // M27 PR1b's three. They are in this table because the corpus below is
        // DERIVED from the controller — a new id-bearing route joins this probe
        // by existing, and the set comparison names it if nobody wrote one.
        {
          name: 'GET versions',
          key: "get('vault/items/:itemId/versions')",
          run: (id) => request(server).get(`/v1/vault/items/${id}/versions`).set(unlocked()),
        },
        {
          name: 'POST undelete',
          key: "post('vault/items/:itemId/undelete')",
          run: (id) => request(server).post(`/v1/vault/items/${id}/undelete`).set(unlocked()),
        },
        {
          name: 'POST restore',
          key: "post('vault/items/:itemId/restore')",
          run: (id) =>
            request(server)
              .post(`/v1/vault/items/${id}/restore`)
              .set({ ...unlocked(), 'if-match': '1' })
              .send({ revision: 1 }),
        },
      ];

      // THE CORPUS IS DERIVED, AND STATED. This test's NAME asserts a property
      // of item routes generally, and a hand-listed set of three is narrower
      // than that claim — a fourth id-bearing route would join the controller
      // and this test would go on passing while saying something it no longer
      // checks. So the controller is the input: every route naming an item id
      // must appear above, in both directions.
      // THE PATTERN MATCHES SUB-PATHS, AND THAT IS THE POINT OF THIS EDIT.
      // M27 PR1a wrote this as `'(vault\/items\/:itemId)'` — the closing quote
      // immediately after the parameter — so it captured the three routes whose
      // path ENDS at the id and was structurally blind to any route beneath it.
      // PR1b adds three such routes. The old pattern would have stayed green
      // while probing none of them: a fence whose input is narrower than its
      // claim goes green for the same reason it is wrong.
      const controller = readFileSync(join(__dirname, '..', 'src', 'vault.controller.ts'), 'utf8');
      const idRoutes = [
        ...controller.matchAll(
          /^\s*@(Get|Put|Delete|Post|Patch)\('(vault\/items\/:itemId[^']*)'\)/gm,
        ),
      ].map((m) => `${(m[1] as string).toLowerCase()}('${m[2] as string}')`);
      // ANCHORED AT LINE START (`^\s*@`, multiline). Without it the scan reads
      // PROSE: a doc comment quoting `@Get('vault/items/:itemId')` counted as a
      // route, which inflated this floor by one and — worse in the other
      // direction — would keep the fence green over a route that had been
      // deleted while a comment still mentioned it. Found because the count
      // came back one higher than the controller has routes.
      expect(idRoutes.length).toBe(6);
      // SETS, not counts: a suffix moving between two routes preserves both.
      expect(new Set(idRoutes)).toEqual(new Set(probes.map((p) => p.key)));

      for (const probe of probes) {
        // Typed as `unknown` bodies on purpose: the assertion compares them as
        // opaque values, and narrowing would invite asserting a shape instead.
        const mine = (await probe.run(absent)) as { status: number; body: unknown };
        const theirs = (await probe.run(strangersItem)) as { status: number; body: unknown };
        expect({ route: probe.name, status: theirs.status, body: theirs.body }).toEqual({
          route: probe.name,
          status: mine.status,
          body: mine.body,
        });
        // And the shared answer is the uniform one, not a shared 403.
        expect(mine.status).toBe(404);
      }

      // The stranger's row is untouched by any of it — a refusal that wrote
      // would be a worse leak than a refusal that answered.
      const after = await admin.query<{ deleted_at: Date | null; revision: number }>(
        `SELECT deleted_at, revision FROM vault_items WHERE id = $1`,
        [strangersItem],
      );
      expect(after.rows[0]).toMatchObject({ deleted_at: null, revision: 1 });
    });

    it('STILL discriminates on create, which is a residual and not an oversight', async () => {
      // THE EXCEPTION TO THE TEST ABOVE, WRITTEN DOWN RATHER THAN OMITTED.
      // `vault_items.id` is a global PRIMARY KEY and the client supplies it, so
      // creating with an id another user already holds raises a unique
      // violation and answers 409 `item_exists`, where an unused id answers
      // 201. That is an existence oracle across users, and it is the one item
      // route the uniform-404 rule does not reach today.
      //
      // NOT FIXED HERE, DELIBERATELY. Closing it means per-user uniqueness —
      // a primary-key change on a live table with a version-capture trigger
      // and its own history — which is a schema decision, not a drive-by in a
      // PR about a concurrency token. Tagged in docs/03 §6vv with an owner.
      // This test exists so the behaviour cannot change silently in either
      // direction: fixing it turns this red, and so does making it worse.
      const strangersItem = randomUUID();
      await admin.query(
        `INSERT INTO vault_items (id, user_id, item_type, blob_ct, blob_version)
         VALUES ($1, $2, 'password', $3, 1)`,
        [strangersItem, STRANGER, Buffer.alloc(64, 9)],
      );
      const blob = Buffer.alloc(64).toString('base64');

      const collision = await request(server)
        .post('/v1/vault/items')
        .set(unlocked())
        .send({ id: strangersItem, itemType: 'password', blob });
      const fresh = await request(server)
        .post('/v1/vault/items')
        .set(unlocked())
        .send({ id: randomUUID(), itemType: 'password', blob });

      // A SOFT-DELETED stranger row answers identically, which is the half of
      // this that a live-row-only probe would miss: no row is ever removed
      // here, so a retired id occupies its key forever and the oracle answers
      // for the whole history of the table rather than its current contents.
      const retired = randomUUID();
      await admin.query(
        `INSERT INTO vault_items
           (id, user_id, item_type, blob_ct, blob_version, deleted_at, deleted_reason)
         VALUES ($1, $2, 'password', $3, 1, now(), 'user_delete')`,
        [retired, STRANGER, Buffer.alloc(64, 11)],
      );
      const onRetired = await request(server)
        .post('/v1/vault/items')
        .set(unlocked())
        .send({ id: retired, itemType: 'password', blob });

      // The answers DIFFER by whether the id is taken — that is the oracle.
      expect(collision.status).toBe(409);
      expect(collision.body).toEqual({ error: 'item_exists' });
      expect(onRetired.status).toBe(409);
      expect(onRetired.body).toEqual({ error: 'item_exists' });
      expect(fresh.status).toBe(201);

      // And the refusal did not write: the stranger's row is as it was, which
      // bounds the leak to existence alone rather than existence plus damage.
      const after = await admin.query<{ user_id: string; revision: number }>(
        `SELECT user_id, revision FROM vault_items WHERE id = $1`,
        [strangersItem],
      );
      expect(after.rows[0]).toMatchObject({ user_id: STRANGER, revision: 1 });
    });

    it('requires step-up as well as an open vault to delete', async () => {
      await request(server)
        .delete(`/v1/vault/items/${itemId}`)
        .set(unlocked())
        .expect(403, { error: 'stepup_required' });
    });

    it('soft-deletes an item under step-up', async () => {
      await request(server)
        .delete(`/v1/vault/items/${itemId}`)
        .set({ ...withStepUp(), [VAULT_SESSION_HEADER]: vaultToken })
        .expect(204);

      const rows = await admin.query<{ deleted_at: Date | null }>(
        `SELECT deleted_at FROM vault_items WHERE id = $1`,
        [itemId],
      );
      // No hard deletes: the row survives, flagged.
      expect(rows.rows[0]!.deleted_at).not.toBeNull();
    });

    describe('the restore reader (M27 PR1b)', () => {
      // Its own item, so the delete/undelete cycles here cannot disturb the
      // sequenced cases above.
      const restorableId = randomUUID();

      /**
       * AN ITEM WITH A GENUINE HISTORY, and it needs its own because `itemId`
       * does NOT have one. PR1a's If-Match test forces `blob_version` away from
       * `revision` with raw SQL (`SET blob_version = 9`) and deliberately does
       * NOT re-encrypt — so from that point every image of that row carries a
       * version its ciphertext was never sealed under. Decryption assertions
       * against it would fail for a reason that is a fixture, not a defect;
       * the first draft of these cases did exactly that.
       *
       * Here every write goes through the real API sealing against
       * `blobVersion + 1`, so each captured pair is one a client actually made.
       */
      const historyId = randomUUID();

      beforeAll(async () => {
        const seal = async (version: number, text: string): Promise<string> =>
          Buffer.from(
            await encryptItem(
              masterKey,
              { userId: OWNER, itemId: historyId, blobVersion: version },
              utf8(text),
            ),
          ).toString('base64');

        await request(server)
          .post('/v1/vault/items')
          .set(unlocked())
          .send({ id: historyId, itemType: 'password', blob: await seal(1, 'first') })
          .expect(201);

        for (const [version, text] of [
          [2, 'second'],
          [3, 'third'],
        ] as const) {
          const live = (
            await request(server).get(`/v1/vault/items/${historyId}`).set(unlocked()).expect(200)
          ).body as VaultItemDto;
          await request(server)
            .put(`/v1/vault/items/${historyId}`)
            .set({ ...unlocked(), 'if-match': String(live.revision) })
            .send({ itemType: 'password', blob: await seal(version, text) })
            .expect(200);
        }
      });

      it('lists prior versions newest first, and every blob still OPENS', async () => {
        // The property that matters is not that a row came back — it is that
        // the ciphertext and the version came back as a MATCHED PAIR. A version
        // handed over beside the wrong number decrypts to nothing, and no
        // status code would say so, which is why this decrypts with the real
        // client crypto rather than asserting shapes.
        const res = await request(server)
          .get(`/v1/vault/items/${historyId}/versions`)
          .set(unlocked())
          .expect(200);
        const page = res.body as { versions: VaultVersionDto[]; nextCursor: string | null };

        expect(page.versions.length).toBeGreaterThanOrEqual(2);
        const revisions = page.versions.map((v) => v.revision);
        expect([...revisions]).toEqual([...revisions].sort((a, b) => b - a));

        for (const version of page.versions) {
          const opened = await decryptItem(
            masterKey,
            { userId: OWNER, itemId: historyId, blobVersion: version.blobVersion },
            new Uint8Array(Buffer.from(version.blob, 'base64')),
          );
          // It decrypted at all — the pair held.
          expect(opened.byteLength).toBeGreaterThan(0);
        }
      });

      it('answers 200 with an empty list for an item that has no history', async () => {
        // NOT a 404. "Yours, nothing captured yet" and "not yours" are different
        // facts and only one of them is the caller's business; collapsing them
        // would tell an owner their own item does not exist.
        const fresh = randomUUID();
        const blob = await encryptItem(
          masterKey,
          { userId: OWNER, itemId: fresh, blobVersion: 1 },
          utf8('never edited'),
        );
        await request(server)
          .post('/v1/vault/items')
          .set(unlocked())
          .send({ id: fresh, itemType: 'password', blob: Buffer.from(blob).toString('base64') })
          .expect(201);

        const res = await request(server)
          .get(`/v1/vault/items/${fresh}/versions`)
          .set(unlocked())
          .expect(200);
        expect(res.body).toEqual({ versions: [], nextCursor: null });
      });

      it('puts a prior version back, moving blob_version BACKWARDS', async () => {
        const before = await request(server)
          .get(`/v1/vault/items/${historyId}/versions`)
          .set(unlocked())
          .expect(200);
        const target = (before.body as { versions: VaultVersionDto[] }).versions.at(-1)!;

        const live = await request(server)
          .get(`/v1/vault/items/${historyId}`)
          .set(unlocked())
          .expect(200);
        const liveDto = live.body as VaultItemDto;
        // ANTI-VACUITY: the restore has to actually move the version, or this
        // passes by restoring the state the row is already in.
        expect(target.blobVersion).toBeLessThan(liveDto.blobVersion);

        const res = await request(server)
          .post(`/v1/vault/items/${historyId}/restore`)
          .set({ ...unlocked(), 'if-match': String(liveDto.revision) })
          .send({ revision: target.revision })
          .expect(200);

        const restored = res.body as VaultItemDto;
        // The blob version went DOWN — legal since migration 005, and the whole
        // reason PR1a had to split the token first.
        expect(restored.blobVersion).toBe(target.blobVersion);
        expect(restored.blobVersion).toBeLessThan(liveDto.blobVersion);
        // The revision went UP, because it is a counter and not a version.
        expect(restored.revision).toBeGreaterThan(liveDto.revision);

        // And the restored blob opens under the restored version.
        const opened = await decryptItem(
          masterKey,
          { userId: OWNER, itemId: historyId, blobVersion: restored.blobVersion },
          new Uint8Array(Buffer.from(restored.blob, 'base64')),
        );
        expect(opened.byteLength).toBeGreaterThan(0);
      });

      it('refuses a restore whose If-Match is the BLOB VERSION, not the revision', async () => {
        const live = (
          await request(server).get(`/v1/vault/items/${historyId}`).set(unlocked()).expect(200)
        ).body as VaultItemDto;
        // The arm where the two DISAGREE is the only one that can tell them
        // apart, and a restore is what makes them disagree.
        expect(live.blobVersion).not.toBe(live.revision);

        await request(server)
          .post(`/v1/vault/items/${historyId}/restore`)
          .set({ ...unlocked(), 'if-match': String(live.blobVersion) })
          .send({ revision: 1 })
          .expect(409, { error: 'version_conflict' });
      });

      it('undeletes a user-deleted item, and says so exactly once', async () => {
        const blob = await encryptItem(
          masterKey,
          { userId: OWNER, itemId: restorableId, blobVersion: 1 },
          utf8('restore me'),
        );
        await request(server)
          .post('/v1/vault/items')
          .set(unlocked())
          .send({
            id: restorableId,
            itemType: 'password',
            blob: Buffer.from(blob).toString('base64'),
          })
          .expect(201);
        await request(server)
          .delete(`/v1/vault/items/${restorableId}`)
          .set({ ...withStepUp(), [VAULT_SESSION_HEADER]: vaultToken })
          .expect(204);

        // It is offered...
        const listed = (
          await request(server).get('/v1/vault/items/restorable').set(unlocked()).expect(200)
        ).body as VaultItemPage;
        expect(listed.items.map((i) => i.id)).toContain(restorableId);

        // ...and comes back with NO If-Match, because recovery must not be
        // harder than the delete that made it necessary.
        const back = await request(server)
          .post(`/v1/vault/items/${restorableId}/undelete`)
          .set(unlocked())
          .expect(200);
        expect((back.body as VaultItemDto).id).toBe(restorableId);

        const row = await admin.query<{ deleted_at: Date | null; deleted_reason: string | null }>(
          `SELECT deleted_at, deleted_reason FROM vault_items WHERE id = $1`,
          [restorableId],
        );
        // BOTH columns move together — migration 004's CHECK refuses anything else.
        expect(row.rows[0]).toEqual({ deleted_at: null, deleted_reason: null });

        // A second undelete is a success that changes nothing rather than a 404
        // or a second event: the item is already where the caller wants it.
        await request(server)
          .post(`/v1/vault/items/${restorableId}/undelete`)
          .set(unlocked())
          .expect(200);
        const restoredEvents = producer.messages
          .map(
            (m) =>
              JSON.parse(m.value) as { action?: string; resourceId?: string; detail?: unknown },
          )
          .filter((e) => e.action === 'vault.item.restored' && e.resourceId === restorableId);
        expect(restoredEvents).toHaveLength(1);
        expect(restoredEvents[0]?.detail).toMatchObject({ kind: 'undelete' });
      });

      it('never offers an image captured while the row was RETIRED', async () => {
        // The undelete above captured the row AS IT WAS — deleted. Writing that
        // image forward would be a "restore" that deletes the item, so the
        // reader must not offer it at all. An absence, not a check at the call
        // site: the arm cannot be reached rather than being refused when it is.
        const res = await request(server)
          .get(`/v1/vault/items/${restorableId}/versions`)
          .set(unlocked())
          .expect(200);
        const versions = (res.body as { versions: VaultVersionDto[] }).versions;

        const images = await admin.query<{ n: string }>(
          `SELECT count(*) AS n FROM vault_items_versions
            WHERE row_id = $1 AND row_data->>'deleted_at' IS NOT NULL`,
          [restorableId],
        );
        // ANTI-VACUITY: such an image must EXIST, or this asserts nothing.
        expect(Number(images.rows[0]!.n)).toBeGreaterThan(0);

        for (const version of versions) {
          const captured = await admin.query<{ deleted_at: string | null }>(
            `SELECT row_data->>'deleted_at' AS deleted_at FROM vault_items_versions
              WHERE row_id = $1 AND revision = $2`,
            [restorableId, version.revision],
          );
          expect({ revision: version.revision, deletedAt: captured.rows[0]?.deleted_at }).toEqual({
            revision: version.revision,
            deletedAt: null,
          });
        }
      });

      it('routes /restorable to the LIST, not to getItem with a bogus id', async () => {
        // Nest matches in declaration order, so this is green only while
        // `@Get('vault/items/restorable')` precedes `@Get('vault/items/:itemId')`.
        // Reorder those two methods and this 200 becomes a 400.
        const res = await request(server)
          .get('/v1/vault/items/restorable')
          .set(unlocked())
          .expect(200);
        expect(res.body).toHaveProperty('items');
      });
    });

    it('locks the vault on request', async () => {
      await request(server).post('/v1/vault/lock').set(unlocked()).expect(204);
      await request(server)
        .get('/v1/vault/items')
        .set(unlocked())
        .expect(403, { error: 'vault_locked' });
    });
  });

  describe('password change', () => {
    it('rejects a replacement without a valid proof', async () => {
      const opened = await openVault();
      const change = await buildKeysetChange({
        userId: OWNER,
        newPassword: 'a brand new vault password',
        secretKey,
        masterKey: new Uint8Array(32),
        keysetAuthKey: new Uint8Array(32), // not the SRP-derived key
        iterations: MIN_ITERATIONS,
      });

      await request(server)
        .put('/v1/vault/keyset')
        .set({ ...withStepUp(), [VAULT_SESSION_HEADER]: opened.token })
        .send({ ...change.payload, proof: change.proof })
        .expect(403, { error: 'invalid_keyset_proof' });
    });

    it('replaces the keyset with a valid proof and keeps existing items readable', async () => {
      const opened = await openVault();
      const newItemId = randomUUID();
      const blob = await encryptItem(
        opened.masterKey,
        { userId: OWNER, itemId: newItemId, blobVersion: 1 },
        utf8('survives the password change'),
      );
      await request(server)
        .post('/v1/vault/items')
        .set({ ...asOwner(), [VAULT_SESSION_HEADER]: opened.token })
        .send({
          id: newItemId,
          itemType: 'secure_note',
          blob: Buffer.from(blob).toString('base64'),
        })
        .expect(201);

      // Recover the raw master key the way the client does for a rotation.
      const preparation = await prepareUnlock({
        userId: OWNER,
        password: VAULT_PASSWORD,
        secretKey,
        kdfParams: enrollment.kdfParams,
        srpSalt: enrollment.srpSalt,
      });
      const masterKeyBytes = await exportMasterKeyBytes({
        userId: OWNER,
        auk: preparation.auk,
        wrappedMasterKey: enrollment.wrappedMasterKey,
      });

      const change = await buildKeysetChange({
        userId: OWNER,
        newPassword: 'a brand new vault password',
        secretKey,
        masterKey: masterKeyBytes,
        keysetAuthKey: opened.keysetAuthKey,
        iterations: MIN_ITERATIONS,
      });

      await request(server)
        .put('/v1/vault/keyset')
        .set({ ...withStepUp(), [VAULT_SESSION_HEADER]: opened.token })
        .send({ ...change.payload, proof: change.proof })
        .expect(200);

      enrollment = change.payload;

      // The old password no longer opens the vault...
      const stale = await request(server)
        .post('/v1/vault/srp/start')
        .set(withStepUp())
        .expect(201)
        .then((res) => res.body as SrpChallenge);
      const staleAttempt = await prepareUnlock({
        userId: OWNER,
        password: VAULT_PASSWORD,
        secretKey,
        kdfParams: stale.kdfParams,
        srpSalt: stale.srpSalt,
      });
      const staleProof = await proveUnlock(staleAttempt, stale.serverPublic);
      await request(server)
        .post('/v1/vault/srp/verify')
        .set(withStepUp())
        .send({
          handshakeId: stale.handshakeId,
          clientPublic: staleAttempt.publicA,
          clientProof: staleProof.m1,
        })
        .expect(401, { error: 'srp_failed' });

      // ...and the new one opens it onto the same master key.
      const reopened = await openVault('a brand new vault password');
      const res = await request(server)
        .get(`/v1/vault/items/${newItemId}`)
        .set({ ...asOwner(), [VAULT_SESSION_HEADER]: reopened.token })
        .expect(200);
      const dto = res.body as VaultItemDto;
      const plaintext = await decryptItem(
        reopened.masterKey,
        { userId: OWNER, itemId: newItemId, blobVersion: dto.blobVersion },
        new Uint8Array(Buffer.from(dto.blob, 'base64')),
      );
      expect(Buffer.from(plaintext).toString('utf8')).toBe('survives the password change');
    });

    it('keeps keyset history but redacts the key material from it', async () => {
      const rows = await admin.query<{ row_data: Record<string, unknown>; actor_id: string }>(
        `SELECT row_data, actor_id FROM vault_keysets_versions WHERE row_id = $1 ORDER BY version_seq`,
        [OWNER],
      );
      expect(rows.rows.length).toBeGreaterThan(0);
      for (const row of rows.rows) {
        // What has audit value survives...
        expect(row.actor_id).toBe(OWNER);
        expect(row.row_data).toHaveProperty('kdf_params');
        expect(row.row_data).toHaveProperty('srp_salt');
        // ...and what would be an attack asset does not.
        expect(row.row_data).not.toHaveProperty('wrapped_master_key');
        expect(row.row_data).not.toHaveProperty('srp_verifier');
      }
    });
  });

  describe('reset', () => {
    it('destroys every item and re-enrolls in one step', async () => {
      const before = await admin.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM vault_items WHERE user_id = $1 AND deleted_at IS NULL`,
        [OWNER],
      );
      expect(Number(before.rows[0]!.count)).toBeGreaterThan(0);

      // ROWS RETIRED BEFORE THIS RESET ARE THE CASE M27 PR1b CLOSES. There has
      // to be at least one already carrying `user_delete`, or the assertion
      // after the reset is about an empty set and proves nothing.
      const retiredBefore = await admin.query<{ id: string }>(
        `SELECT id FROM vault_items
          WHERE user_id = $1 AND deleted_at IS NOT NULL AND deleted_reason = 'user_delete'`,
        [OWNER],
      );
      expect(retiredBefore.rows.length).toBeGreaterThan(0);
      const retiredAt = await admin.query<{ deleted_at: Date }>(
        `SELECT deleted_at FROM vault_items WHERE id = $1`,
        [retiredBefore.rows[0]!.id],
      );

      const fresh = await createVaultEnrollment({
        userId: OWNER,
        password: 'starting over completely',
        iterations: MIN_ITERATIONS,
      });

      const res = await request(server)
        .post('/v1/vault/reset')
        .set(withStepUp())
        .send(fresh.enrollment.payload)
        .expect(200);
      expect((res.body as { itemsDestroyed: number }).itemsDestroyed).toBeGreaterThan(0);

      const after = await admin.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM vault_items WHERE user_id = $1 AND deleted_at IS NULL`,
        [OWNER],
      );
      expect(after.rows[0]!.count).toBe('0');

      // The rows are still there - no hard deletes - just permanently opaque.
      const retained = await admin.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM vault_items WHERE user_id = $1`,
        [OWNER],
      );
      expect(Number(retained.rows[0]!.count)).toBeGreaterThan(0);

      // THE ROWS RETIRED EARLIER ARE RELABELLED, and this is the defect PR0's
      // discriminator left open (M27 PR1b). `softDeleteAllForUser` carries
      // `WHERE deleted_at IS NULL`, so an item the owner deleted a minute
      // before this reset is untouched by it and would keep saying
      // `user_delete` — restorable — while the keyset that opened it has just
      // been replaced. The restore list would offer a blob that can never
      // decrypt, and the failure would arrive as a silent AEAD error on click:
      // a control firing wearing the face of an outage, which is the exact
      // shape migration 004 was added to prevent.
      const relabelled = await admin.query<{ deleted_reason: string; deleted_at: Date }>(
        `SELECT deleted_reason, deleted_at FROM vault_items WHERE id = $1`,
        [retiredBefore.rows[0]!.id],
      );
      expect(relabelled.rows[0]!.deleted_reason).toBe('vault_reset');
      // `deleted_at` is UNCHANGED: when the owner retired it stays true, and
      // only its decryptability changed here.
      expect(relabelled.rows[0]!.deleted_at).toEqual(retiredAt.rows[0]!.deleted_at);
      // The reset RECORDS the relabel, separately from what it retired itself.
      // In the audit trail rather than the response: the caller already knows
      // they deleted those rows, and the route's shape is a client contract
      // this change has no reason to move. The two counts are distinct keys
      // because they mean different things — one set was live a moment ago,
      // the other only just became undecryptable.
      const resetEvent = producer.messages
        .map((m) => JSON.parse(m.value) as { action?: string; detail?: Record<string, unknown> })
        .filter((e) => e.action === 'vault.reset')
        .at(-1);
      expect(resetEvent?.detail?.['itemsRelabelled']).toBeGreaterThan(0);
      expect(resetEvent?.detail?.['itemsRelabelled']).not.toEqual(
        resetEvent?.detail?.['itemsDestroyed'],
      );

      // And the new password opens the new, empty vault.
      const opened = await openVault('starting over completely', fresh.enrollment.secretKey);
      const list = await request(server)
        .get('/v1/vault/items')
        .set({ ...asOwner(), [VAULT_SESSION_HEADER]: opened.token })
        .expect(200);
      expect((list.body as { items: VaultItemDto[] }).items).toHaveLength(0);

      // AND THE RESTORE LIST OFFERS NOTHING, which is the property the relabel
      // exists to produce: every row this user has is now `vault_reset`, and
      // `RESTORABLE_REASONS` excludes it because its blob is cryptographically
      // dead. Asserted through the ROUTE rather than the column, because the
      // column being right is only useful if the reader agrees.
      const restorable = await request(server)
        .get('/v1/vault/items/restorable')
        .set({ ...asOwner(), [VAULT_SESSION_HEADER]: opened.token })
        .expect(200);
      expect((restorable.body as VaultItemPage).items).toEqual([]);

      // AND ASKING FOR ONE DIRECTLY IS REFUSED IN ITS OWN WORDS. Not a 404 —
      // the row is there and its owner can see it in their own history — and
      // not a 500, because nothing failed. `item_unrestorable` is a third
      // answer because it needs a third remedy: there is no action the caller
      // can take, and telling them "not found" would send them looking.
      const deadRow = await admin.query<{ id: string }>(
        `SELECT id FROM vault_items WHERE user_id = $1 AND deleted_reason = 'vault_reset' LIMIT 1`,
        [OWNER],
      );
      expect(deadRow.rows.length).toBe(1);
      await request(server)
        .post(`/v1/vault/items/${deadRow.rows[0]!.id}/undelete`)
        .set({ ...asOwner(), [VAULT_SESSION_HEADER]: opened.token })
        .expect(409, { error: 'item_unrestorable' });
    });

    it('records a reset notification that did NOT land as delivered_at NULL', async () => {
      // The M14 review's confirmed regression. PR2 changed the port from
      // throw-based to outcome-based and updated every call site EXCEPT this
      // one, so `deliveredAt = this.clock()` was reached unconditionally: every
      // reset recorded its notification as delivered, on the one route where a
      // bearer token destroys a Zone A vault, where that record is the only
      // compensating control the route's own docstring names.
      //
      // The notifier above reports non-delivery WITHOUT throwing, which is what
      // every production adapter does now — the old `catch` was simply
      // unreachable.
      const { rows } = await admin.query<{ delivered_at: Date | null }>(
        `SELECT delivered_at FROM ${schema}.emergency_access_notifications
          WHERE user_id = $1 AND kind = 'reset' ORDER BY created_at DESC LIMIT 1`,
        [OWNER],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.delivered_at).toBeNull();
    });

    it('records unverified_recipient when a reset DID reach an unproved address', async () => {
      // Round 2 of the M14 review: the emit shipped with no test anywhere, and
      // the int case added alongside it builds the one state where it cannot
      // fire (an undelivered send). Reset was the single notification path that
      // could never produce this evidence, because it discarded the outcome —
      // so a vault destroyed and announced to an address nobody proved left no
      // record of that anywhere.
      notifierOutcome.delivered = true;
      notifierOutcome.recipientVerified = false;
      try {
        const fresh = await createVaultEnrollment({
          userId: OWNER,
          password: 'a third password entirely',
          iterations: MIN_ITERATIONS,
        });
        await request(server)
          .post('/v1/vault/reset')
          .set(withStepUp())
          .send(fresh.enrollment.payload)
          .expect(200);
      } finally {
        notifierOutcome.delivered = false;
      }

      const actions = producer.messages
        .map((m) => JSON.parse(m.value) as { action?: string })
        .map((event) => event.action);
      expect(actions).toContain('vault.emergency.unverified_recipient');
    });

    it('refuses to reset a vault that was never enrolled', async () => {
      await request(server)
        .post('/v1/vault/reset')
        .set(bearer('stepup', STRANGER))
        .send(enrollment)
        .expect(404, { error: 'keyset_not_found' });
    });
  });

  describe('audit', () => {
    it('emits the actions the vault is required to record', () => {
      const actions = new Set(
        producer.messages
          .filter((m) => m.topic === TOPICS.auditEvents)
          .map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action),
      );
      for (const required of [
        'vault.keyset.created',
        'vault.keyset.updated',
        'vault.opened',
        'vault.open.failed',
        'vault.items.listed',
        'vault.item.created',
        'vault.item.accessed',
        'vault.item.updated',
        'vault.item.deleted',
        'vault.reset',
        'vault.session.revoked',
      ]) {
        expect(actions).toContain(required);
      }
    });

    it('never carries vault content, passwords or key material', () => {
      const payloads = producer.messages.map((m) => m.value).join('\n');
      expect(payloads).not.toContain(VAULT_PASSWORD);
      expect(payloads).not.toContain(ITEM_SECRET);
      expect(payloads).not.toContain(secretKey);
      expect(payloads).not.toContain('bank.example.com');
      expect(payloads).not.toContain(enrollment.wrappedMasterKey);
      expect(payloads).not.toContain(enrollment.srpVerifier);
    });

    it('publishes only to the audit topic - there is no vault domain topic', () => {
      expect(new Set(producer.messages.map((m) => m.topic))).toEqual(new Set([TOPICS.auditEvents]));
    });
  });
});
