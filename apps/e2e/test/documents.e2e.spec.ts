/**
 * Milestone 4 acceptance E2E: template publish → step-up-gated generation →
 * upload ingest (clean + EICAR-rejected) → encrypted search → step-up-gated
 * deletion, with every emitted audit event ingested into the audit service's
 * hash-chained store and the chain cryptographically verified, every domain
 * event validated as IDs/enums-only, and the content/PII firewall asserted
 * across the bus.
 *
 * Transport note: the documents producer and audit ingestor are bridged
 * in-process (the exact bytes documents hands to Kafka are handed to the
 * ingestor) — same deliberate M1 bridge, Kafka broker hop tracked in docs/04.
 *
 * Deep `dist` imports are sanctioned HERE ONLY: this is a test-only package;
 * runtime services never import each other (docs/04 boundary rule 4).
 */
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { randomBytes, randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { Test, type TestingModule } from '@nestjs/testing';
import supertest from 'supertest';
import { Client, type QueryResultRow } from 'pg';
import {
  AuditEventSchema,
  DocumentStatusChangedEvent,
  DocumentVersionCreatedEvent,
  TOPICS,
  type MfaLevel,
} from '@estate/contracts';
import { AuditEmitter } from '@estate/audit-emitter';
import { Migrator } from '@estate/db';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import { AppModule } from '@estate/service-documents/dist/app.module';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AUDIT_PRODUCER } from '@estate/service-documents/dist/di-tokens';
import { EICAR_TEST_STRING } from '@estate/service-documents/dist/malware-scanner';
import { LocalFsObjectStore } from '@estate/service-documents/dist/object-store';
import { publishTemplates } from '@estate/service-documents/dist/template-publish-cli';
import { AuditIngestor } from '@estate/service-audit/dist/ingestor';
import { ChainVerifier } from '@estate/service-audit/dist/verifier';

/**
 * Stands in for identity introspection (the real cross-service path is
 * covered by session-verification.e2e.spec.ts): `<level>:<userId>` bearer
 * tokens verify to sessions of that level.
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

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

function migrationsDirOf(pkg: string): string {
  return join(dirname(require.resolve(`${pkg}/package.json`)), 'migrations');
}

function templatesDirOf(pkg: string): string {
  return join(dirname(require.resolve(`${pkg}/package.json`)), 'templates');
}

function schemaScopedUrl(base: string, schema: string): string {
  const url = new URL(base);
  url.searchParams.set('options', `-c search_path=${schema}`);
  return url.toString();
}

/** PDF-sniffing fixture whose "scanned" text is literal bytes (StubOcr). */
function pdfFixture(text: string, extra: Buffer = Buffer.alloc(0)): Buffer {
  return Buffer.concat([
    Buffer.from(`%PDF-1.4\n1 0 obj\n<< >>\nstream\n${text}\nendstream\n`, 'latin1'),
    extra,
    Buffer.from('\n%%EOF\n', 'latin1'),
  ]);
}

const TESTATOR = 'Avery E2E Testator';
const DEED_TEXT = 'Deed for the shore cabin recorded in Windmere County';

describeIfPg('documents: generate/upload/search/delete → audit chain + domain topic', () => {
  jest.setTimeout(180_000);
  const stamp = Date.now();
  const documentsSchema = `e2e_docs_${stamp}`;
  const auditSchema = `e2e_docs_audit_${stamp}`;
  const OWNER = randomUUID();
  const STRANGER = randomUUID();
  let objectDir: string;
  let admin: Client;
  let auditDb: Client;
  let app: ReturnType<TestingModule['createNestApplication']>;
  let producer: InMemoryAuditProducer;

  beforeAll(async () => {
    const baseUrl = process.env['PG_TEST_URL']!;
    objectDir = mkdtempSync(join(tmpdir(), 'estate-docs-e2e-'));
    admin = new Client({ connectionString: baseUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${documentsSchema}`);
    await admin.query(`CREATE SCHEMA ${auditSchema}`);

    // --- documents side: migrate, publish the real templates, boot the module ---
    const documentsClient = new Client({
      connectionString: schemaScopedUrl(baseUrl, documentsSchema),
    });
    await documentsClient.connect();
    await new Migrator(documentsClient, migrationsDirOf('@estate/service-documents')).migrate();
    const publishReport = await publishTemplates(
      {
        query: async <T extends QueryResultRow>(
          text: string,
          values: unknown[] = [],
        ): Promise<T[]> => (await documentsClient.query<T>(text, values)).rows,
      },
      new LocalFsObjectStore(objectDir),
      new AuditEmitter(new InMemoryAuditProducer(), () => new Date()),
      [
        {
          path: 'CA/will/v1.json',
          bytes: readFileSync(
            join(templatesDirOf('@estate/service-documents'), 'CA', 'will', 'v1.json'),
          ),
        },
      ],
    );
    expect(publishReport.activated).toContain('will/CA/v1');
    await documentsClient.end();

    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, documentsSchema);
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['SEARCH_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['OBJECT_STORE_MODE'] = 'fs';
    process.env['OBJECT_STORE_DIR'] = objectDir;
    delete process.env['KAFKA_BROKERS']; // NODE_ENV=test ⇒ in-memory producer
    delete process.env['SCANNER_MODE']; // ⇒ stub scanner (EICAR-detecting)
    delete process.env['OCR_MODE']; // ⇒ stub OCR

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(fakeVerifier)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    producer = app.get<InMemoryAuditProducer>(AUDIT_PRODUCER);
    expect(producer).toBeInstanceOf(InMemoryAuditProducer);

    // --- audit side: migrate on its own schema-scoped session ---
    auditDb = new Client({ connectionString: schemaScopedUrl(baseUrl, auditSchema) });
    await auditDb.connect();
    await new Migrator(auditDb, migrationsDirOf('@estate/service-audit')).migrate();
  });

  afterAll(async () => {
    await app?.close();
    await auditDb?.end();
    await admin.query(`DROP SCHEMA ${documentsSchema} CASCADE`);
    await admin.query(`DROP SCHEMA ${auditSchema} CASCADE`);
    await admin.end();
    rmSync(objectDir, { recursive: true, force: true });
  });

  it('runs the M4 flow and produces a verifiable audit chain + valid domain events', async () => {
    const http = supertest(app.getHttpServer() as Parameters<typeof supertest>[0]);
    const owner = bearer('mfa', OWNER);
    const stepUp = bearer('stepup', OWNER);
    const stranger = bearer('mfa', STRANGER);

    // Generation is step-up gated (docs/01 §5): refused for a plain session.
    const generateBody = {
      docType: 'will',
      state: 'CA',
      variables: {
        testatorName: TESTATOR,
        county: 'Windmere',
        executorName: 'Emery Executor',
        hasAlternateExecutor: false,
        hasMinorChildren: false,
        residuaryBeneficiaryName: 'Rowan Residuary',
      },
    };
    await http.post('/v1/documents/generate').set(owner).send(generateBody).expect(403);
    const generated = await http
      .post('/v1/documents/generate')
      .set(stepUp)
      .send(generateBody)
      .expect(201);
    const willId = (generated.body as { documentId: string }).documentId;

    // Reading content back decrypts under the per-document DEK — the decrypt
    // itself must land in the audit chain (crypto.field.decrypted).
    const content = await http
      .get(`/v1/documents/${willId}/versions/1/content`)
      .set(owner)
      .expect(200);
    expect((content.body as { content: string }).content).toContain(TESTATOR);

    // Upload ingest: EICAR is rejected and never stored; a clean deed lands.
    await http
      .post('/v1/documents/upload')
      .set(owner)
      .send({
        kind: 'other',
        title: 'Suspicious attachment',
        mime: 'application/pdf',
        contentBase64: pdfFixture('payload', Buffer.from(EICAR_TEST_STRING)).toString('base64'),
      })
      .expect(422, { error: 'malware_detected' });
    const uploaded = await http
      .post('/v1/documents/upload')
      .set(owner)
      .send({
        kind: 'property',
        title: 'Shore cabin deed',
        mime: 'application/pdf',
        contentBase64: pdfFixture(DEED_TEXT).toString('base64'),
      })
      .expect(201);
    const deedId = (uploaded.body as { documentId: string; ocrIndexed: boolean }).documentId;
    expect((uploaded.body as { ocrIndexed: boolean }).ocrIndexed).toBe(true);

    // Encrypted search: the owner finds both documents through the per-user
    // index; a stranger's identical queries find nothing.
    const byOcr = await http
      .post('/v1/documents/search')
      .set(owner)
      .send({ query: 'windmere deed' })
      .expect(200);
    expect((byOcr.body as Array<{ documentId: string }>).map((d) => d.documentId)).toEqual([
      deedId,
    ]);
    const byRendered = await http
      .post('/v1/documents/search')
      .set(owner)
      .send({ query: 'emery executor' })
      .expect(200);
    expect((byRendered.body as Array<{ documentId: string }>).map((d) => d.documentId)).toEqual([
      willId,
    ]);
    await http
      .post('/v1/documents/search')
      .set(stranger)
      .send({ query: 'windmere deed' })
      .expect(200, []);

    // Execution attestation + step-up-gated deletion of the upload.
    await http
      .post(`/v1/documents/${willId}/status`)
      .set(owner)
      .send({ status: 'signed' })
      .expect(200);
    await http.delete(`/v1/documents/${deedId}`).set(owner).expect(403);
    await http.delete(`/v1/documents/${deedId}`).set(stepUp).expect(200);
    await http
      .post('/v1/documents/search')
      .set(owner)
      .send({ query: 'windmere deed' })
      .expect(200, []);

    // --- bridge: exact produced audit bytes → audit ingestor → verified chain ---
    const auditMessages = producer.messages.filter((m) => m.topic === TOPICS.auditEvents);
    const ingestor = new AuditIngestor(auditDb);
    for (const message of auditMessages) {
      const result = await ingestor.ingest(message.value);
      expect(result.status).toBe('appended');
    }
    const verdict = await new ChainVerifier(auditDb).verify();
    expect(verdict).toEqual({ ok: true, count: auditMessages.length });

    const actions = new Set(
      auditMessages.map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action),
    );
    for (const required of [
      'document.generated',
      'document.content.viewed',
      'document.uploaded',
      'document.scan.rejected',
      'document.ocr.indexed',
      'document.status.changed',
      'document.deleted',
      'crypto.field.decrypted',
    ]) {
      expect(actions).toContain(required);
    }

    // --- domain topic: every envelope parses and carries IDs/enums only ---
    const domainMessages = producer.messages.filter((m) => m.topic === TOPICS.documentEvents);
    expect(domainMessages.length).toBeGreaterThanOrEqual(3);
    for (const message of domainMessages) {
      const parsed = JSON.parse(message.value) as { type: string };
      const schema =
        parsed.type === 'document.version.created'
          ? DocumentVersionCreatedEvent
          : DocumentStatusChangedEvent;
      const envelope = schema.parse(JSON.parse(message.value));
      expect([willId, deedId]).toContain(envelope.payload.documentId);
      expect(message.key).toBe(envelope.payload.documentId);
    }

    // --- content/PII firewall: nothing sensitive ever crosses the bus ---
    const allPayloads = producer.messages.map((m) => m.value).join('\n');
    for (const secret of [
      TESTATOR,
      'Emery',
      'Rowan',
      'Windmere',
      'Shore cabin',
      'Suspicious attachment',
      EICAR_TEST_STRING,
    ]) {
      expect(allPayloads).not.toContain(secret);
    }
  });
});
