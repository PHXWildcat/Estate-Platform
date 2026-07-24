import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { S3Client } from '@aws-sdk/client-s3';
import { Client, type QueryResultRow } from 'pg';
import { AuditEmitter } from '@estate/audit-emitter';
import { InMemoryAuditProducer, KafkaAuditProducer } from './audit-producer';
import type { Queryable } from './db';
import { LocalFsObjectStore, type ObjectStore } from './object-store';
import { S3ObjectStore } from './s3-object-store';
import { templateObjectKey } from './template-engine';
import { parseTemplateSource, type TemplateSource } from './template-model';
import { activateTemplate, findTemplateByKey, insertTemplate } from './templates.repo';

/**
 * Template publish CLI — the ONLY write path into document_templates.
 * "Versioned like code with legal sign-off gates" (docs/01 §2.4) is literal:
 * sources live in `apps/services/documents/templates/`, carry mandatory
 * legalReview metadata (schema-enforced), get reviewed in git like any other
 * change, and this CLI pushes them to the object store + DB.
 *
 *   node dist/template-publish-cli.js [templatesDir]
 *
 * Env: DATABASE_URL (required); OBJECT_STORE_MODE/OBJECT_STORE_DIR or
 * OBJECT_STORE_BUCKET+AWS_REGION (as in config.ts); KAFKA_BROKERS (optional —
 * publication/activation audit events emit when brokers are configured).
 *
 * Invariants:
 *  - A published (docType, state, version) is IMMUTABLE: re-publishing
 *    identical bytes is a no-op; different bytes for the same version is an
 *    error (bump the version).
 *  - `activate: true` makes that source the single active version for its
 *    (docType, state); the previous active is deactivated in the same
 *    transaction (the partial unique index enforces at-most-one).
 */

interface PublishReport {
  published: string[];
  activated: string[];
  skipped: string[];
}

function labelOf(source: TemplateSource): string {
  return `${source.docType}/${source.state}/v${source.version}`;
}

function listTemplateFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listTemplateFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      out.push(full);
    }
  }
  return out.sort();
}

function objectStoreFromEnv(env: NodeJS.ProcessEnv): ObjectStore {
  if (env['OBJECT_STORE_MODE'] === 's3') {
    const bucket = env['OBJECT_STORE_BUCKET'];
    const region = env['AWS_REGION'];
    if (!bucket || !region) {
      throw new Error('OBJECT_STORE_BUCKET and AWS_REGION are required for s3 mode');
    }
    return new S3ObjectStore(new S3Client({ region }), bucket);
  }
  return new LocalFsObjectStore(env['OBJECT_STORE_DIR'] ?? '.object-store');
}

export async function publishTemplates(
  db: Queryable,
  store: ObjectStore,
  emitter: AuditEmitter,
  files: ReadonlyArray<{ path: string; bytes: Buffer }>,
): Promise<PublishReport> {
  const report: PublishReport = { published: [], activated: [], skipped: [] };
  for (const file of files) {
    const source = parseTemplateSource(JSON.parse(file.bytes.toString('utf8')));
    const label = labelOf(source);
    const sha = createHash('sha256').update(file.bytes).digest();
    const existing = await findTemplateByKey(db, source.docType, source.state, source.version);
    let row: { id: string };
    if (existing) {
      if (!existing.body_sha256.equals(sha)) {
        throw new Error(
          `${label}: published version content differs from source — published versions are immutable; bump the version`,
        );
      }
      report.skipped.push(label);
      row = existing;
    } else {
      const key = templateObjectKey(source.docType, source.state, source.version);
      await store.put(key, file.bytes);
      const id = await insertTemplate(db, {
        docType: source.docType,
        state: source.state,
        version: source.version,
        bodyRef: key,
        bodySha256: sha,
        legalReviewBy: source.legalReview.by,
        legalReviewAt: new Date(source.legalReview.at),
        executionRequirements: source.executionRequirements,
        variables: source.variables,
      });
      row = { id };
      report.published.push(label);
      await emitter.emit({
        action: 'document.template.published',
        actorId: null,
        actorType: 'operator',
        onBehalfOf: null,
        resourceType: 'document_template',
        resourceId: id,
        sessionId: null,
        detail: { docType: source.docType, state: source.state, version: source.version },
      });
    }
    if (source.activate) {
      const current = await findTemplateByKey(db, source.docType, source.state, source.version);
      if (current && !current.active) {
        await activateTemplate(db, row.id, source.docType, source.state);
        report.activated.push(label);
        await emitter.emit({
          action: 'document.template.activated',
          actorId: null,
          actorType: 'operator',
          onBehalfOf: null,
          resourceType: 'document_template',
          resourceId: row.id,
          sessionId: null,
          detail: { docType: source.docType, state: source.state, version: source.version },
        });
      }
    }
  }
  return report;
}

async function main(): Promise<void> {
  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    process.stderr.write('DATABASE_URL is required\n');
    process.exitCode = 1;
    return;
  }
  const templatesDir = process.argv[2] ?? join(__dirname, '..', 'templates');
  const files = listTemplateFiles(templatesDir).map((path) => ({
    path,
    bytes: readFileSync(path),
  }));
  const brokers = (process.env['KAFKA_BROKERS'] ?? '')
    .split(',')
    .map((b) => b.trim())
    .filter((b) => b.length > 0);
  const producer =
    brokers.length > 0 ? new KafkaAuditProducer(brokers) : new InMemoryAuditProducer();
  const emitter = new AuditEmitter(producer, () => new Date());
  const store = objectStoreFromEnv(process.env);
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    await client.query('BEGIN');
    const db: Queryable = {
      query: async <T extends QueryResultRow>(text: string, values: unknown[] = []): Promise<T[]> =>
        (await client.query<T>(text, values)).rows,
    };
    const report = await publishTemplates(db, store, emitter, files);
    await client.query('COMMIT');
    process.stdout.write(
      `published: ${report.published.join(', ') || '(none)'}\n` +
        `activated: ${report.activated.join(', ') || '(none)'}\n` +
        `unchanged: ${report.skipped.join(', ') || '(none)'}\n`,
    );
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    await client.end();
    if (producer instanceof KafkaAuditProducer) {
      await producer.disconnect();
    }
  }
}

if (require.main === module) {
  void main().catch((err: unknown) => {
    // Operational errors only: labels and identifiers, never user data.
    process.stderr.write(`${err instanceof Error ? err.message : 'publish failed'}\n`);
    process.exitCode = 1;
  });
}
