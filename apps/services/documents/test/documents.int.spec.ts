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
import {
  SERVICE_CREDENTIAL_HEADER,
  SESSION_VERIFIER,
  type SessionContext,
  type SessionVerifier,
} from '@estate/auth-guard';
import { Client, type QueryResultRow } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AUDIT_PRODUCER, PG_POOL_CONFIG } from '../src/di-tokens';
import type {
  ContentDto,
  DocumentDetailDto,
  DocumentDto,
  GenerateResult,
  UploadResult,
  VersionDto,
} from '../src/documents.service';
import { EICAR_TEST_STRING } from '../src/malware-scanner';
import { LocalFsObjectStore } from '../src/object-store';
import { publishTemplates } from '../src/template-publish-cli';
import type { Queryable } from '../src/db';
import { pdfFixture } from './support';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const OWNER = randomUUID();
const STRANGER = randomUUID();
const INTERNAL_CREDENTIAL = 'int-test-documents-internal-credential';
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
      audience: 'account',
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
      expect(applied).toContain('002_document_vault.sql');
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
    process.env['SEARCH_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['OBJECT_STORE_MODE'] = 'fs';
    process.env['OBJECT_STORE_DIR'] = objectDir;
    // M9 PR2: the internal legal-hold route is exercised with the real guard.
    process.env['DOCUMENTS_INTERNAL_TOKEN'] = INTERNAL_CREDENTIAL;
    delete process.env['KAFKA_BROKERS'];
    delete process.env['SCANNER_MODE']; // ⇒ stub scanner (EICAR-detecting)
    delete process.env['OCR_MODE']; // ⇒ stub OCR (printable-run extraction)

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
    // The document READ advertises exactly that ladder, one rung at a time,
    // from the template's own sha256-verified requirements — so a client
    // renders the attestations this instrument in this state needs rather than
    // a hardcoded ladder that could offer a will a no-witness path (M12 PR2).
    const rungs = async (): Promise<string[]> =>
      (
        (await request(server).get(`/v1/documents/${documentId}`).set(asOwner()).expect(200))
          .body as DocumentDetailDto
      ).allowedTransitions;
    expect(await rungs()).toEqual(['signed']);
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
    // 'notarized' is NOT offered: CA's will template requires no notary, so
    // that rung does not exist for this document.
    expect(await rungs()).toEqual(['executed', 'revoked']);
    const res = await request(server)
      .post(`/v1/documents/${documentId}/status`)
      .set(asOwner())
      .send({ status: 'executed', executedAt: '2026-07-23' })
      .expect(200);
    const dto = res.body as DocumentDetailDto;
    expect(dto.executionStatus).toBe('executed');
    expect(dto.executedAt).toBe('2026-07-23');
    // The transition's own answer carries the NEW ladder, so a client never
    // renders a stale one for a round trip.
    expect(dto.allowedTransitions).toEqual(['revoked', 'superseded']);
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

  it('the internal legal-hold route: credential-gated, estate-wide, idempotent, audited (M9 PR2)', async () => {
    // The route's first-ever test, driven exactly as settlement drives it —
    // over HTTP with the service credential and the real guard, never a user
    // bearer. A fresh estate owner keeps the estate-wide count deterministic.
    const estateOwner = randomUUID();
    const upload = async (title: string): Promise<string> => {
      const res = await request(server)
        .post('/v1/documents/upload')
        .set(bearer('mfa', estateOwner))
        .send({
          kind: 'legal',
          title,
          mime: 'application/pdf',
          contentBase64: pdfFixture(`estate paper ${title}`).toString('base64'),
        })
        .expect(201);
      return (res.body as UploadResult).documentId;
    };
    const heldDocA = await upload('estate-paper-a');
    const heldDocB = await upload('estate-paper-b');
    const caseId = randomUUID();
    const holdBody = { ownerUserId: estateOwner, hold: true, caseId };

    // No credential, a user bearer, or a wrong credential: 401, nothing set.
    await request(server).put('/internal/v1/legal-hold').send(holdBody).expect(401);
    await request(server)
      .put('/internal/v1/legal-hold')
      .set(bearer('stepup', estateOwner))
      .send(holdBody)
      .expect(401);
    await request(server)
      .put('/internal/v1/legal-hold')
      .set(SERVICE_CREDENTIAL_HEADER, 'not-the-credential')
      .send(holdBody)
      .expect(401);
    // Malformed body fails closed before any write.
    await request(server)
      .put('/internal/v1/legal-hold')
      .set(SERVICE_CREDENTIAL_HEADER, INTERNAL_CREDENTIAL)
      .send({ ownerUserId: estateOwner, hold: 'yes', caseId })
      .expect(400, { error: 'invalid_request' });

    // The real call sweeps the whole estate...
    const set = await request(server)
      .put('/internal/v1/legal-hold')
      .set(SERVICE_CREDENTIAL_HEADER, INTERNAL_CREDENTIAL)
      .send(holdBody)
      .expect(200);
    expect(set.body).toEqual({ changed: 2 });
    // ...blocks deletion while held...
    await request(server)
      .delete(`/v1/documents/${heldDocA}`)
      .set(bearer('stepup', estateOwner))
      .expect(409, { error: 'legal_hold' });
    // ...and is idempotent, so settlement can re-drive it after a commit
    // failure without a second effect.
    const again = await request(server)
      .put('/internal/v1/legal-hold')
      .set(SERVICE_CREDENTIAL_HEADER, INTERNAL_CREDENTIAL)
      .send(holdBody)
      .expect(200);
    expect(again.body).toEqual({ changed: 0 });

    // Audited with ids/enums only: the case id and the count, never a title.
    const audited = producer.messages
      .filter((m) => m.topic === TOPICS.auditEvents)
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
      .filter((e) => e.action === 'document.legal_hold.set');
    expect(audited.length).toBeGreaterThanOrEqual(2);
    expect(audited[0]!.detail).toEqual({ hold: true, changed: 2, caseId });
    expect(audited[0]!.actorType).toBe('service');
    expect(audited[0]!.actorId).toBeNull();

    // ...and the VERSION HISTORY agrees with the audit event: a hold the
    // platform imposed is attributed to the system, never to the owner, who
    // could not have performed it. In a §5.1 fraud investigation this history
    // is evidence — it must not read as though the decedent froze their own
    // documents. (M9 security review.)
    const { rows: heldVersions } = await admin.query<{ actor_id: string | null }>(
      `SELECT actor_id FROM documents_versions WHERE row_id = $1 ORDER BY version_seq DESC LIMIT 1`,
      [heldDocA],
    );
    expect(heldVersions[0]!.actor_id).toBe('00000000-0000-0000-0000-000000000000');
    expect(heldVersions[0]!.actor_id).not.toBe(estateOwner);

    // Clearing restores deletability — the reject/void path.
    const cleared = await request(server)
      .put('/internal/v1/legal-hold')
      .set(SERVICE_CREDENTIAL_HEADER, INTERNAL_CREDENTIAL)
      .send({ ownerUserId: estateOwner, hold: false, caseId })
      .expect(200);
    expect(cleared.body).toEqual({ changed: 2 });
    await request(server)
      .delete(`/v1/documents/${heldDocB}`)
      .set(bearer('stepup', estateOwner))
      .expect(200);
  });

  it('uploads a clean PDF: scanned, OCR-indexed, ciphertext at rest, searchable', async () => {
    const bytes = pdfFixture(`Deed for ${TESTATOR} recorded in Marlow County`);
    const res = await request(server)
      .post('/v1/documents/upload')
      .set(asOwner())
      .send({
        kind: 'property',
        title: 'Lake house deed',
        mime: 'application/pdf',
        contentBase64: bytes.toString('base64'),
      })
      .expect(201);
    const upload = res.body as UploadResult;
    expect(upload.executionStatus).toBe('draft');
    expect(upload.ocrIndexed).toBe(true);

    // Content + OCR artifact at rest are ciphertext (no PDF marker, no PII).
    const { rows: versions } = await admin.query<{ object_key: string; ocr_indexed: boolean }>(
      `SELECT object_key, ocr_indexed FROM document_versions WHERE document_id = $1`,
      [upload.documentId],
    );
    expect(versions[0]!.ocr_indexed).toBe(true);
    const blob = readFileSync(join(objectDir, ...versions[0]!.object_key.split('/')));
    expect(blob.includes(Buffer.from('%PDF'))).toBe(false);
    expect(blob.includes(Buffer.from('Marlow'))).toBe(false);
    const ocrArtifact = readFileSync(join(objectDir, 'documents', upload.documentId, 'v1-ocr'));
    expect(ocrArtifact.includes(Buffer.from('Marlow'))).toBe(false);

    // Search tokens are HMACs only — never plaintext-derived visible bytes.
    const { rows: tokens } = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM document_search_tokens WHERE document_id = $1`,
      [upload.documentId],
    );
    expect(tokens[0]!.n).toBeGreaterThan(3);

    // Owner finds it; a stranger's identical query finds nothing.
    const found = (
      await request(server)
        .post('/v1/documents/search')
        .set(asOwner())
        .send({ query: 'marlow deed' })
        .expect(200)
    ).body as DocumentDto[];
    expect(found.map((d) => d.documentId)).toContain(upload.documentId);
    const strangers = (
      await request(server)
        .post('/v1/documents/search')
        .set(asStranger())
        .send({ query: 'marlow deed' })
        .expect(200)
    ).body as DocumentDto[];
    expect(strangers).toEqual([]);

    // Binary content round-trips base64 through the audited decrypt path.
    const content = (
      await request(server)
        .get(`/v1/documents/${upload.documentId}/versions/1/content`)
        .set(asOwner())
        .expect(200)
    ).body as ContentDto;
    expect(content.encoding).toBe('base64');
    expect(Buffer.from(content.content, 'base64').equals(bytes)).toBe(true);
  });

  it('rejects an EICAR-carrying upload: 422, audited, nothing stored', async () => {
    const before = await admin.query<{ n: number }>(`SELECT count(*)::int AS n FROM documents`);
    await request(server)
      .post('/v1/documents/upload')
      .set(asOwner())
      .send({
        kind: 'other',
        title: 'Suspicious attachment',
        mime: 'application/pdf',
        contentBase64: pdfFixture('payload', Buffer.from(EICAR_TEST_STRING)).toString('base64'),
      })
      .expect(422, { error: 'malware_detected' });
    const after = await admin.query<{ n: number }>(`SELECT count(*)::int AS n FROM documents`);
    expect(after.rows[0]!.n).toBe(before.rows[0]!.n);
    const rejection = producer.messages
      // Domain-topic envelopes carry no `action`; only audit messages parse
      // under AuditEventSchema.
      .filter((m) => m.topic === TOPICS.auditEvents)
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
      .find((e) => e.action === 'document.scan.rejected')!;
    expect(rejection.detail['reason']).toBe('infected');
  });

  it('rejects mislabeled and undeclared content types (422)', async () => {
    await request(server)
      .post('/v1/documents/upload')
      .set(asOwner())
      .send({
        kind: 'other',
        title: 'Polyglot',
        mime: 'application/pdf',
        contentBase64: Buffer.from('<!doctype html><script>x</script>').toString('base64'),
      })
      .expect(422, { error: 'unsupported_content' });
    await request(server)
      .post('/v1/documents/upload')
      .set(asOwner())
      .send({
        kind: 'other',
        title: 'Markup',
        mime: 'image/svg+xml',
        contentBase64: Buffer.from('<svg onload=alert(1)>').toString('base64'),
      })
      .expect(422, { error: 'unsupported_content' });
  });

  it('audit PII firewall: no produced message ever carries plaintext content', () => {
    expect(producer.messages.length).toBeGreaterThan(0);
    for (const message of [...producer.messages, ...publishProducer.messages]) {
      expect(message.value).not.toContain(TESTATOR);
      expect(message.value).not.toContain(EXECUTOR);
      expect(message.value).not.toContain('Alameda');
      expect(message.value).not.toContain('Riley');
      expect(message.value).not.toContain('Marlow');
      expect(message.value).not.toContain('Lake house');
    }
  });
});
