/**
 * End-to-end integration test against a real Postgres, gated exactly like
 * packages/db: set PG_TEST_URL to run (CI service container). Runs the
 * service's real migrations into a scratch schema, publishes the REAL in-repo
 * template sources through the real publish-CLI logic into a temp filesystem
 * object store, boots the Nest app over both, and drives the full flow with
 * supertest: template catalog, step-up-gated generation, ciphertext at rest
 * (DB metadata + object store blobs), audited decryption, the execution
 * ladder, version history, legal hold, soft delete with actor-attributed
 * version capture, and the audit PII firewall. Also verifies the docs/02
 * schema conventions via checkConventions.
 */
import 'reflect-metadata';
import type { Server } from 'node:http';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import { AuditEmitter } from '@estate/audit-emitter';
import { checkConventions, Migrator } from '@estate/db';
import {
  AuditEventSchema,
  DocumentVersionCreatedEvent,
  TOPICS,
  type MfaLevel,
} from '@estate/contracts';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import { Client, type QueryResultRow } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { InMemoryAuditProducer } from '../src/audit-producer';
import { AUDIT_PRODUCER, PG_POOL_CONFIG } from '../src/di-tokens';
import type { ContentDto, DocumentDto, GenerateResult, VersionDto } from '../src/documents.service';
import { LocalFsObjectStore } from '../src/object-store';
import { publishTemplates } from '../src/template-publish-cli';
import type { Queryable } from '../src/db';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const OWNER = randomUUID();
const STRANGER = randomUUID();
const TESTATOR = 'Alexandra Q. Integration';
const EXECUTOR = 'Jordan T. Executor';

/**
 * Stands in for real identity introspection: a bearer token of the form
 * `<level>:<userId>` verifies to that session (mirrors what CallerGuard would
 * get from `HttpSessionVerifier` → identity's `/v1/auth/session`). A malformed
 * token verifies to null (⇒ 401). The real cross-service path is proven in the
 * session-verification e2e; here we isolate the document service.
 */
const fakeVerifier: SessionVerifier = {
  verify: (token) => {
    const m = /^(mfa|stepup):([0-9a-f-]{36})$/.exec(token);
    if (!m) {
      return Promise.resolve(null);
    }
    const [, level, userId] = m;
    const ctx: SessionContext = {
      userId: userId!,
      sessionId: '00000000-0000-4000-8000-000000000000',
      mfaLevel: level as MfaLevel,
      stepupExpiresAt: level === 'stepup' ? new Date(Date.now() + 5 * 60 * 1000) : null,
    };
    return Promise.resolve(ctx);
  },
};

const bearer = (level: 'mfa' | 'stepup', userId: string): Record<string, string> => ({
  authorization: `Bearer ${level}:${userId}`,
});

const TEMPLATES_DIR = join(__dirname, '..', 'templates');

function templateFiles(): Array<{ path: string; bytes: Buffer }> {
  const files: Array<{ path: string; bytes: Buffer }> = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.json')) files.push({ path: full, bytes: readFileSync(full) });
    }
  };
  walk(TEMPLATES_DIR);
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

describeIfPg('document service end to end', () => {
  jest.setTimeout(120_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `docsvc_test_${Date.now()}`;
  let objectDir: string;
  let admin: Client;
  let app: INestApplication;
  let server: Server;
  let producer: InMemoryAuditProducer;
  let publishProducer: InMemoryAuditProducer;
  let documentId: string;

  const asOwner = (): Record<string, string> => bearer('mfa', OWNER);
  const asStranger = (): Record<string, string> => bearer('mfa', STRANGER);
  const withStepUp = (): Record<string, string> => bearer('stepup', OWNER);

  const adminQueryable = (): Queryable => ({
    query: async <T extends QueryResultRow>(text: string, values: unknown[] = []): Promise<T[]> =>
      (await admin.query<T>(text, values)).rows,
  });

  beforeAll(async () => {
    objectDir = mkdtempSync(join(tmpdir(), 'estate-docs-int-'));
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Unqualified trigger inserts (…_versions) must resolve on this raw client.
    await admin.query(`SET search_path TO ${schema}, public`);

    const migrClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrClient.connect();
    try {
      const migrator = new Migrator(migrClient, `${__dirname}/../migrations`);
      const { applied } = await migrator.migrate();
      expect(applied).toContain('001_documents_schema.sql');
    } finally {
      await migrClient.end();
    }

    // Publish the real in-repo template sources through the real CLI logic.
    publishProducer = new InMemoryAuditProducer();
    const report = await publishTemplates(
      adminQueryable(),
      new LocalFsObjectStore(objectDir),
      new AuditEmitter(publishProducer, () => new Date()),
      templateFiles(),
    );
    expect(report.published).toContain('will/CA/v1');
    expect(report.activated).toContain('will/CA/v1');

    process.env['DATABASE_URL'] = pgUrl;
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['OBJECT_STORE_MODE'] = 'fs';
    process.env['OBJECT_STORE_DIR'] = objectDir;
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
    await app?.close();
    await admin?.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin?.end();
    rmSync(objectDir, { recursive: true, force: true });
  });

  it('implements the docs/02 schema conventions (checker passes)', async () => {
    const violations = await checkConventions(
      { query: (text, values) => admin.query(text, values ?? []) },
      {
        schema,
        businessTables: ['document_templates', 'documents'],
        appendOnlyTables: [
          'document_versions',
          'document_templates_versions',
          'documents_versions',
        ],
      },
    );
    expect(violations).toEqual([]);
  });

  it('publish is idempotent, versions are immutable, and one active per pair is DB-enforced', async () => {
    const again = await publishTemplates(
      adminQueryable(),
      new LocalFsObjectStore(objectDir),
      new AuditEmitter(publishProducer, () => new Date()),
      templateFiles(),
    );
    expect(again.published).toEqual([]);
    expect(again.skipped.length).toBeGreaterThanOrEqual(3);

    const { rows: counts } = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM document_templates WHERE doc_type = 'will' AND state = 'CA'`,
    );
    expect(counts[0]!.n).toBe(1);

    // A second active row for (will, CA) must violate ux_document_templates_active.
    await expect(
      admin.query(
        `INSERT INTO document_templates
           (doc_type, state, version, body_ref, body_sha256, legal_review_by, legal_review_at,
            execution_requirements, variables, active)
         VALUES ('will', 'CA', 99, 'templates/CA/will/v99.json', '\\x00', 'x', now(), '{}', '[]', true)`,
      ),
    ).rejects.toMatchObject({ code: '23505' });

    // Publication/activation audit events are contract-valid.
    for (const message of publishProducer.messages) {
      AuditEventSchema.parse(JSON.parse(message.value));
    }
  });

  it('rejects missing and forged bearer tokens (401)', async () => {
    await request(server).get('/v1/documents').expect(401, { error: 'unauthorized' });
    await request(server)
      .get('/v1/documents')
      .set('authorization', 'Bearer forged-token')
      .expect(401, { error: 'unauthorized' });
  });

  it('serves the template catalog for a state (variables included, active only)', async () => {
    const res = await request(server).get('/v1/templates?state=CA').set(asOwner()).expect(200);
    const catalog = res.body as Array<{ docType: string; variables: Array<{ name: string }> }>;
    expect(catalog).toHaveLength(1);
    expect(catalog[0]!.docType).toBe('will');
    expect(catalog[0]!.variables.map((v) => v.name)).toContain('testatorName');
    await request(server).get('/v1/templates?state=ZZ').set(asOwner()).expect(400);
  });

  it('refuses generation without a FRESH step-up session (403), never a header', async () => {
    await request(server)
      .post('/v1/documents/generate')
      .set(asOwner())
      .send({ docType: 'will', state: 'CA', variables: {} })
      .expect(403);
    // The retired M2 header must not resurrect the bypass.
    await request(server)
      .post('/v1/documents/generate')
      .set(asOwner())
      .set('x-estate-stepup-verified', 'true')
      .send({ docType: 'will', state: 'CA', variables: {} })
      .expect(403);
  });

  it('generates a CA will under step-up: only ciphertext at rest, everywhere', async () => {
    const res = await request(server)
      .post('/v1/documents/generate')
      .set(withStepUp())
      .send({
        docType: 'will',
        state: 'CA',
        variables: {
          testatorName: TESTATOR,
          county: 'Alameda',
          executorName: EXECUTOR,
          hasAlternateExecutor: false,
          hasMinorChildren: false,
          residuaryBeneficiaryName: 'Riley Residuary',
        },
      })
      .expect(201);
    const ack = res.body as GenerateResult;
    documentId = ack.documentId;
    expect(ack.version).toBe(1);
    expect(ack.executionStatus).toBe('generated');

    // The DB row is metadata only; the per-document DEK exists and is bound
    // to the document (per-object DEKs, docs/01 §4).
    const { rows: docs } = await admin.query<{ user_id: string; dek_id: string }>(
      `SELECT user_id, dek_id, execution_status FROM documents WHERE id = $1`,
      [documentId],
    );
    expect(docs[0]!.user_id).toBe(OWNER);
    const { rows: deks } = await admin.query<{ document_id: string; destroyed_at: Date | null }>(
      `SELECT document_id, destroyed_at FROM document_deks WHERE dek_id = $1`,
      [docs[0]!.dek_id],
    );
    expect(deks[0]!.document_id).toBe(documentId);
    expect(deks[0]!.destroyed_at).toBeNull();

    // The stored blob is AEAD ciphertext: no plaintext markers, no PII.
    const { rows: versions } = await admin.query<{ object_key: string }>(
      `SELECT object_key, content_sha256 FROM document_versions WHERE document_id = $1`,
      [documentId],
    );
    const blob = readFileSync(join(objectDir, ...versions[0]!.object_key.split('/')));
    expect(blob.includes(Buffer.from(TESTATOR))).toBe(false);
    expect(blob.includes(Buffer.from('<!doctype html>'))).toBe(false);
  });

  it('422s an intake payload the template schema rejects (undeclared key)', async () => {
    await request(server)
      .post('/v1/documents/generate')
      .set(withStepUp())
      .send({
        docType: 'will',
        state: 'CA',
        variables: { testatorName: TESTATOR, smuggled: 'data' },
      })
      .expect(422, { error: 'invalid_variables' });
  });

  it('decrypts content for the owner (audited), denies strangers, 404s others', async () => {
    const res = await request(server)
      .get(`/v1/documents/${documentId}/versions/1/content`)
      .set(asOwner())
      .expect(200);
    const content = res.body as ContentDto;
    expect(content.mime).toBe('text/html');
    expect(content.content).toContain(`I, ${TESTATOR}`);
    expect(content.content).toContain('data-state="CA"');

    await request(server)
      .get(`/v1/documents/${documentId}/versions/1/content`)
      .set(asStranger())
      .expect(403, { error: 'forbidden' });
    await request(server)
      .get(`/v1/documents/${randomUUID()}/versions/1/content`)
      .set(asOwner())
      .expect(404);

    const actions = producer.messages
      .filter((m) => m.topic === TOPICS.auditEvents)
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action);
    expect(actions).toContain('crypto.field.decrypted');
    expect(actions).toContain('document.content.viewed');
    expect(actions).toContain('document.generated');
  });

  it('publishes the IDs-only domain event for the generation', () => {
    const domain = producer.messages.filter((m) => m.topic === TOPICS.documentEvents);
    expect(domain.length).toBeGreaterThanOrEqual(1);
    const event = DocumentVersionCreatedEvent.parse(JSON.parse(domain[0]!.value));
    expect(event.payload.documentId).toBe(documentId);
    expect(event.payload.version).toBe(1);
  });

  it('creates version 2 under step-up with If-Match; stale If-Match conflicts', async () => {
    await request(server)
      .post(`/v1/documents/${documentId}/versions`)
      .set(withStepUp())
      .set('if-match', '99')
      .send({ variables: { testatorName: TESTATOR } })
      .expect(409);
    const res = await request(server)
      .post(`/v1/documents/${documentId}/versions`)
      .set(withStepUp())
      .set('if-match', '1')
      .send({
        variables: {
          testatorName: TESTATOR,
          county: 'Alameda',
          executorName: 'Elliot Replacement',
          hasAlternateExecutor: false,
          hasMinorChildren: false,
          residuaryBeneficiaryName: 'Riley Residuary',
        },
      })
      .expect(201);
    expect((res.body as GenerateResult).version).toBe(2);

    const versions = (
      await request(server).get(`/v1/documents/${documentId}/versions`).set(asOwner()).expect(200)
    ).body as VersionDto[];
    expect(versions.map((v) => v.version)).toEqual([1, 2]);

    const v2 = (
      await request(server)
        .get(`/v1/documents/${documentId}/versions/2/content`)
        .set(asOwner())
        .expect(200)
    ).body as ContentDto;
    expect(v2.content).toContain('Elliot Replacement');
  });

  it('walks the execution ladder per CA requirements; refuses skips and regeneration', async () => {
    // CA will: witnesses 2, no notarization ⇒ signed → witnessed → executed.
    await request(server)
      .post(`/v1/documents/${documentId}/status`)
      .set(asOwner())
      .send({ status: 'executed', executedAt: '2026-07-23' })
      .expect(409);
    await request(server)
      .post(`/v1/documents/${documentId}/status`)
      .set(asOwner())
      .send({ status: 'signed' })
      .expect(200);
    await request(server)
      .post(`/v1/documents/${documentId}/status`)
      .set(asOwner())
      .send({ status: 'executed', executedAt: '2026-07-23' })
      .expect(409);
    // Content is frozen once signing starts.
    await request(server)
      .post(`/v1/documents/${documentId}/versions`)
      .set(withStepUp())
      .send({ variables: { testatorName: TESTATOR } })
      .expect(409, { error: 'invalid_status' });
    await request(server)
      .post(`/v1/documents/${documentId}/status`)
      .set(asOwner())
      .send({ status: 'witnessed' })
      .expect(200);
    const res = await request(server)
      .post(`/v1/documents/${documentId}/status`)
      .set(asOwner())
      .send({ status: 'executed', executedAt: '2026-07-23' })
      .expect(200);
    const dto = res.body as DocumentDto;
    expect(dto.executionStatus).toBe('executed');
    expect(dto.executedAt).toBe('2026-07-23');
  });

  it('legal hold blocks deletion; without it, deletion is step-up gated and soft', async () => {
    await admin.query(`UPDATE documents SET legal_hold = true WHERE id = $1`, [documentId]);
    await request(server)
      .delete(`/v1/documents/${documentId}`)
      .set(withStepUp())
      .expect(409, { error: 'legal_hold' });
    await admin.query(`UPDATE documents SET legal_hold = false WHERE id = $1`, [documentId]);

    await request(server).delete(`/v1/documents/${documentId}`).set(asOwner()).expect(403);
    await request(server).delete(`/v1/documents/${documentId}`).set(withStepUp()).expect(200);
    await request(server).get(`/v1/documents/${documentId}`).set(asOwner()).expect(404);

    // Soft delete: the row survives with deleted_at; version history is intact;
    // the shadow table captured the change attributed to the acting owner.
    const { rows: docs } = await admin.query<{ deleted_at: Date | null }>(
      `SELECT deleted_at FROM documents WHERE id = $1`,
      [documentId],
    );
    expect(docs[0]!.deleted_at).not.toBeNull();
    const { rows: versions } = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM document_versions WHERE document_id = $1`,
      [documentId],
    );
    expect(versions[0]!.n).toBe(2);
    const { rows: shadow } = await admin.query<{ actor_id: string }>(
      `SELECT actor_id FROM documents_versions WHERE row_id = $1 ORDER BY version_seq DESC LIMIT 1`,
      [documentId],
    );
    expect(shadow[0]!.actor_id).toBe(OWNER);
  });

  it('audit PII firewall: no produced message ever carries plaintext content', () => {
    expect(producer.messages.length).toBeGreaterThan(0);
    for (const message of [...producer.messages, ...publishProducer.messages]) {
      expect(message.value).not.toContain(TESTATOR);
      expect(message.value).not.toContain(EXECUTOR);
      expect(message.value).not.toContain('Alameda');
      expect(message.value).not.toContain('Riley');
    }
  });
});
