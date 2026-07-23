/**
 * End-to-end integration test against a real Postgres, gated exactly like
 * packages/db: set PG_TEST_URL to run (CI service container; locally e.g.
 * postgres://estate:estate_dev@localhost:5434/core). Runs the service's real
 * migrations into a scratch schema, boots the Nest app over it with an
 * in-memory audit producer, and drives the profile/contacts flow with
 * supertest — including the docs/03 §5.5 ABAC read boundary end to end.
 */
import 'reflect-metadata';
import type { Server } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import { checkConventions, Migrator } from '@estate/db';
import { TOPICS } from '@estate/contracts';
import { DekConflictError } from '@estate/crypto';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import { Client } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { InMemoryAuditProducer } from '../src/audit-producer';
import { PgDekRepository } from '../src/dek.repository';
import { AUDIT_PRODUCER, PG_POOL_CONFIG } from '../src/di-tokens';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

/**
 * Stands in for real identity introspection: a bearer token `mfa:<userId>`
 * verifies to that session (what CallerGuard would get from HttpSessionVerifier
 * → identity's /v1/auth/session); a malformed token verifies to null (⇒ 401).
 * Profile has no step-up routes. The real cross-service path is proven in the
 * session-verification e2e.
 */
const fakeVerifier: SessionVerifier = {
  verify: (token) => {
    const m = /^mfa:([0-9a-f-]{36})$/.exec(token);
    if (!m) {
      return Promise.resolve(null);
    }
    const ctx: SessionContext = {
      userId: m[1]!,
      sessionId: '00000000-0000-4000-8000-000000000000',
      mfaLevel: 'mfa',
      stepupExpiresAt: null,
    };
    return Promise.resolve(ctx);
  },
};

const OWNER = randomUUID();
const GRANTEE = randomUUID();
const STRANGER = randomUUID();
const LEGAL_NAME = 'Jane Quincy Public';
const NAMED_CONTACT = 'Named Beneficiary Contact';
const OTHER_CONTACT = 'Unrelated Private Contact';

describeIfPg('profile & contacts service end to end', () => {
  jest.setTimeout(120_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `profsvc_test_${Date.now()}`;
  let admin: Client;
  let app: INestApplication;
  let server: Server;
  let producer: InMemoryAuditProducer;

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Put the scratch schema on the admin connection's search_path too: the
    // convention versions triggers run `INSERT INTO <table>_versions`
    // UNQUALIFIED, so a raw admin UPDATE that fires a trigger (e.g. setting
    // linked_user_id below) must resolve those names against the scratch schema.
    // (In production each cluster is its own DB with tables in `public`, so the
    // app pool's search_path already covers this — only this raw client needs it.)
    await admin.query(`SET search_path TO ${schema}, public`);

    const migrClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrClient.connect();
    try {
      const migrator = new Migrator(migrClient, `${__dirname}/../migrations`);
      const { applied } = await migrator.migrate();
      expect(applied).toContain('001_core_schema.sql');
      expect(applied).toContain('002_dek_unique_active.sql');
    } finally {
      await migrClient.end();
    }

    process.env['DATABASE_URL'] = pgUrl;
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['EMAIL_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS'];

    producer = new InMemoryAuditProducer();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AUDIT_PRODUCER)
      .useValue(producer)
      .overrideProvider(PG_POOL_CONFIG)
      .useValue({ connectionString: pgUrl, options: `-c search_path=${schema}` })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(fakeVerifier)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    server = app.getHttpServer() as Server;
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  // The gateway-injected `x-estate-user-id` header is replaced by the caller's
  // bearer token; asUser now yields the Authorization header value.
  const asUser = (id: string): string => `Bearer mfa:${id}`;

  it('rejects a request without the gateway-injected user header (401)', async () => {
    const res = await request(server).get('/v1/profile');
    expect(res.status).toBe(401);
  });

  it('upserts an encrypted profile and reads it back decrypted', async () => {
    const put = await request(server).put('/v1/profile').set('authorization', asUser(OWNER)).send({
      legalName: LEGAL_NAME,
      ssn: '123456789',
      maritalStatus: 'married',
      stateOfResidence: 'CA',
    });
    expect(put.status).toBe(200);

    // Ciphertext at rest — the plaintext legal name never appears in the column.
    const { rows } = await admin.query(
      `SELECT legal_name_ct, ssn_last4_ct, state_of_residence FROM ${schema}.profiles WHERE user_id = $1`,
      [OWNER],
    );
    const row = rows[0] as {
      legal_name_ct: Buffer;
      ssn_last4_ct: Buffer;
      state_of_residence: string;
    };
    expect(row.legal_name_ct.toString('utf8')).not.toContain('Jane');
    expect(row.state_of_residence).toBe('CA'); // plaintext by design (template driver)

    const get = await request(server).get('/v1/profile').set('authorization', asUser(OWNER));
    expect(get.status).toBe(200);
    const view = get.body as { legalName: string; ssnLast4: string; stateOfResidence: string };
    expect(view.legalName).toBe(LEGAL_NAME);
    expect(view.ssnLast4).toBe('6789');
    expect(view.stateOfResidence).toBe('CA');
  });

  let namedId: string;
  let otherId: string;
  let linkedContactId: string;
  let roleAssignmentId: string;

  it('owner creates contacts (encrypted) and captures a version row on update', async () => {
    const named = await request(server)
      .post('/v1/contacts')
      .set('authorization', asUser(OWNER))
      .send({ name: NAMED_CONTACT, email: 'named@example.com' });
    expect(named.status).toBe(201);
    namedId = (named.body as { id: string }).id;

    const other = await request(server)
      .post('/v1/contacts')
      .set('authorization', asUser(OWNER))
      .send({ name: OTHER_CONTACT });
    expect(other.status).toBe(201);
    otherId = (other.body as { id: string }).id;

    // The contact through which GRANTEE is a platform user (invite accepted).
    const linked = await request(server)
      .post('/v1/contacts')
      .set('authorization', asUser(OWNER))
      .send({ name: 'Grantee Person' });
    linkedContactId = (linked.body as { id: string }).id;
    await admin.query(`UPDATE ${schema}.contacts SET linked_user_id = $1 WHERE id = $2`, [
      GRANTEE,
      linkedContactId,
    ]);

    // Update a contact → the versions shadow table captures the prior row.
    const upd = await request(server)
      .put(`/v1/contacts/${namedId}`)
      .set('authorization', asUser(OWNER))
      .send({ name: NAMED_CONTACT, email: 'named@example.com', relationship: 'friend' });
    expect(upd.status).toBe(200);
    const { rows } = await admin.query(
      `SELECT count(*)::int AS n FROM ${schema}.contacts_versions WHERE row_id = $1`,
      [namedId],
    );
    expect((rows[0] as { n: number }).n).toBe(1);
  });

  it('owner grants GRANTEE a scope naming ONLY the named contact', async () => {
    const ra = await request(server)
      .post('/v1/role-assignments')
      .set('authorization', asUser(OWNER))
      .send({
        contactId: linkedContactId,
        role: 'beneficiary',
        scopeType: 'asset',
        scopeId: namedId,
      });
    expect(ra.status).toBe(201);
    roleAssignmentId = (ra.body as { id: string }).id;

    const perm = await request(server)
      .post(`/v1/role-assignments/${roleAssignmentId}/permissions`)
      .set('authorization', asUser(OWNER))
      .send({ resource: 'contact', action: 'read' });
    expect(perm.status).toBe(201);
  });

  it('§5.5: the grant-holder reads ONLY the named contact; the other is denied', async () => {
    const allowed = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts/${namedId}`)
      .set('authorization', asUser(GRANTEE));
    expect(allowed.status).toBe(200);
    expect((allowed.body as { name: string }).name).toBe(NAMED_CONTACT);

    const denied = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts/${otherId}`)
      .set('authorization', asUser(GRANTEE));
    expect(denied.status).toBe(403);
    expect(denied.body).toEqual({ error: 'forbidden' });

    // The list is filtered to the named contact only — no enumeration.
    const list = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts`)
      .set('authorization', asUser(GRANTEE));
    expect(list.status).toBe(200);
    const names = (list.body as Array<{ name: string }>).map((c) => c.name);
    expect(names).toEqual([NAMED_CONTACT]);
  });

  it('a stranger with no grant is denied both the list and a single read', async () => {
    const list = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts`)
      .set('authorization', asUser(STRANGER));
    expect(list.status).toBe(403);

    const one = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts/${namedId}`)
      .set('authorization', asUser(STRANGER));
    expect(one.status).toBe(403);
  });

  it('owner sees all their contacts (owner path)', async () => {
    const list = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts`)
      .set('authorization', asUser(OWNER));
    expect(list.status).toBe(200);
    expect((list.body as unknown[]).length).toBe(3);
  });

  it('concurrent first-writes cannot mint two active DEKs (unique index + adoption)', async () => {
    const newUser = randomUUID();
    const results = await Promise.all(
      [1, 2, 3, 4].map((i) =>
        request(server)
          .post('/v1/contacts')
          .set('authorization', asUser(newUser))
          .send({ name: `Race Contact ${i}` }),
      ),
    );
    for (const res of results) {
      expect(res.status).toBe(201);
    }
    const { rows } = await admin.query(
      `SELECT count(*)::int AS n FROM ${schema}.deks WHERE user_id = $1 AND destroyed_at IS NULL`,
      [newUser],
    );
    expect((rows[0] as { n: number }).n).toBe(1);
  });

  it('translates a duplicate active-DEK insert to DekConflictError (23505)', async () => {
    const repo = app.get(PgDekRepository);
    const userId = randomUUID();
    const record = {
      userId,
      kekAlias: 'local',
      wrappedKey: randomBytes(32),
      createdAt: new Date(),
      destroyedAt: null,
    };
    await repo.insert({ ...record, dekId: randomUUID() });
    await expect(repo.insert({ ...record, dekId: randomUUID() })).rejects.toBeInstanceOf(
      DekConflictError,
    );
  });

  it('emitted the required audit actions and never leaked PII on the wire', () => {
    const auditActions = producer.messages
      .filter((m) => m.topic === TOPICS.auditEvents)
      .map((m) => (JSON.parse(m.value) as { action: string }).action);
    expect(auditActions).toEqual(
      expect.arrayContaining([
        'profile.updated',
        'contact.created',
        'contact.updated',
        'role.granted',
        'permission.granted',
        'crypto.field.decrypted', // every read decrypts through FieldCrypto
      ]),
    );
    // PII firewall: no plaintext name/legal-name on any emitted message.
    for (const message of producer.messages) {
      expect(message.value).not.toContain(LEGAL_NAME);
      expect(message.value).not.toContain(NAMED_CONTACT);
      expect(message.value).not.toContain(OTHER_CONTACT);
    }
  });

  it('the migrated core schema satisfies the docs/02 conventions (checkConventions)', async () => {
    const violations = await checkConventions(
      { query: (text: string, values?: unknown[]) => admin.query(text, values) },
      {
        schema,
        businessTables: ['family_members', 'contacts', 'role_assignments'],
        appendOnlyTables: [
          'profiles_versions',
          'family_members_versions',
          'contacts_versions',
          'role_assignments_versions',
        ],
      },
    );
    expect(violations).toEqual([]);
  });
});
