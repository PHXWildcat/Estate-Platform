import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { FieldCrypto, LocalKmsProvider, type DekRecord, type DekRepository } from '@estate/crypto';
import type { DocumentsConfig } from '../src/config';
import { ContentCipher } from '../src/content-cipher';
import type { Db, Queryable } from '../src/db';
import { SearchIndexer } from '../src/search-indexer';
import type { DocumentRow } from '../src/documents.repo';
import { EventsService } from '../src/events.service';
import { InMemoryAuditProducer } from '@estate/kafka';
import {
  assertValidKey,
  ObjectConflictError,
  ObjectNotFoundError,
  type ObjectStore,
} from '../src/object-store';
import { templateObjectKey } from '../src/template-engine';
import type { TemplateSource } from '../src/template-model';
import type { TemplateRow } from '../src/templates.repo';
import type { VersionRow } from '../src/versions.repo';

/** In-memory DekRepository for the real FieldCrypto (no Postgres needed). */
export class MemoryDeks implements DekRepository {
  private readonly rows = new Map<string, DekRecord>();
  findActiveByUser(subjectId: string): Promise<DekRecord | null> {
    for (const r of this.rows.values()) {
      if (r.userId === subjectId && r.destroyedAt === null) return Promise.resolve(r);
    }
    return Promise.resolve(null);
  }
  findById(dekId: string): Promise<DekRecord | null> {
    return Promise.resolve(this.rows.get(dekId) ?? null);
  }
  insert(record: DekRecord): Promise<void> {
    this.rows.set(record.dekId, record);
    return Promise.resolve();
  }
  markDestroyed(dekId: string, at: Date): Promise<void> {
    const r = this.rows.get(dekId);
    if (r) this.rows.set(dekId, { ...r, destroyedAt: at });
    return Promise.resolve();
  }
}

/**
 * A real ContentCipher over a real FieldCrypto with an in-memory DEK store.
 * Pass an EventsService to mirror app.module's wiring (every decrypt emits
 * `crypto.field.decrypted` with the DOCUMENT id as the resource).
 */
export function buildCipher(
  deks: DekRepository = new MemoryDeks(),
  events?: EventsService,
): ContentCipher {
  const crypto = new FieldCrypto(
    LocalKmsProvider.generate(),
    deks,
    events
      ? async (event): Promise<void> => {
          await events.audit.emit({
            action: 'crypto.field.decrypted',
            actorId: event.actorId,
            actorType: event.actorType,
            onBehalfOf: null,
            resourceType: 'document',
            resourceId: event.userId,
            sessionId: null,
            detail: { dekId: event.dekId, field: event.field, purpose: event.purpose },
          });
        }
      : (): void => undefined,
    { kekAlias: 'documents/kek' },
  );
  return new ContentCipher(crypto);
}

/** In-memory ObjectStore honoring the port's key + immutability contract. */
export class MemoryObjectStore implements ObjectStore {
  readonly objects = new Map<string, Buffer>();

  put(key: string, body: Buffer): Promise<void> {
    assertValidKey(key);
    const existing = this.objects.get(key);
    if (existing) {
      if (!existing.equals(body)) {
        return Promise.reject(new ObjectConflictError());
      }
      return Promise.resolve();
    }
    this.objects.set(key, Buffer.from(body));
    return Promise.resolve();
  }

  get(key: string): Promise<Buffer> {
    assertValidKey(key);
    const body = this.objects.get(key);
    return body ? Promise.resolve(Buffer.from(body)) : Promise.reject(new ObjectNotFoundError());
  }

  exists(key: string): Promise<boolean> {
    assertValidKey(key);
    return Promise.resolve(this.objects.has(key));
  }
}

/** No-op events double capturing nothing (services under test don't assert on it). */
export const noopEvents = new Proxy(
  {},
  { get: () => (): Promise<void> => Promise.resolve() },
) as never;

/** Real EventsService over the in-memory producer (assert on messages). */
export function capturingEvents(): { events: EventsService; producer: InMemoryAuditProducer } {
  const producer = new InMemoryAuditProducer();
  const events = new EventsService(producer, () => new Date());
  return { events, producer };
}

const rejectRawSql = (): Promise<never> =>
  Promise.reject(new Error('unit tests must not issue raw SQL'));

const DUMMY_TX: Queryable = { query: rejectRawSql };

/**
 * Db double: withTransaction just runs the callback (no rollback semantics —
 * transactional atomicity is integration-tested against real Postgres).
 */
export function fakeDb(): Db {
  return {
    query: rejectRawSql,
    withTransaction: async <T>(_actor: string, fn: (tx: Queryable) => Promise<T>): Promise<T> =>
      fn(DUMMY_TX),
    onModuleDestroy: () => Promise.resolve(),
  } as unknown as Db;
}

/** In-memory DocumentsRepo with live/soft-deleted semantics. */
export class FakeDocuments {
  readonly rows = new Map<string, DocumentRow>();

  getLive(_q: Queryable | Db, id: string): Promise<DocumentRow | null> {
    const row = this.rows.get(id);
    return Promise.resolve(row && row.deleted_at === null ? { ...row } : null);
  }
  lockById(_q: Queryable, id: string): Promise<DocumentRow | null> {
    return this.getLive(_q, id);
  }
  /** M7 PR2: settlement's estate-wide legal hold. */
  setLegalHoldForOwner(_tx: Queryable, userId: string, hold: boolean): Promise<number> {
    let changed = 0;
    for (const row of this.rows.values()) {
      if (row.user_id === userId && row.deleted_at === null && row.legal_hold !== hold) {
        row.legal_hold = hold;
        changed += 1;
      }
    }
    return Promise.resolve(changed);
  }
  listLiveByUser(_q: Queryable | Db, userId: string): Promise<DocumentRow[]> {
    return Promise.resolve(
      [...this.rows.values()]
        .filter((r) => r.user_id === userId && r.deleted_at === null)
        .map((r) => ({ ...r })),
    );
  }
  insert(
    _q: Queryable,
    row: {
      id: string;
      userId: string;
      docType: DocumentRow['doc_type'];
      templateId: string | null;
      source: DocumentRow['source'];
      title: string;
      executionStatus: DocumentRow['execution_status'];
      dekId: string;
    },
  ): Promise<void> {
    this.rows.set(row.id, {
      id: row.id,
      user_id: row.userId,
      doc_type: row.docType,
      template_id: row.templateId,
      source: row.source,
      title: row.title,
      current_version: 1,
      execution_status: row.executionStatus,
      executed_at: null,
      legal_hold: false,
      sealed: false,
      dek_id: row.dekId,
      created_at: new Date(),
      updated_at: new Date(),
      deleted_at: null,
    });
    return Promise.resolve();
  }
  bumpVersion(_q: Queryable, id: string, version: number): Promise<void> {
    const row = this.rows.get(id)!;
    this.rows.set(id, {
      ...row,
      current_version: version,
      execution_status: 'generated',
      executed_at: null,
      updated_at: new Date(),
    });
    return Promise.resolve();
  }
  updateStatus(
    _q: Queryable,
    id: string,
    status: DocumentRow['execution_status'],
    executedAt: string | null,
  ): Promise<void> {
    const row = this.rows.get(id)!;
    this.rows.set(id, {
      ...row,
      execution_status: status,
      executed_at: executedAt,
      updated_at: new Date(),
    });
    return Promise.resolve();
  }
  updateTitle(_q: Queryable, id: string, title: string): Promise<void> {
    const row = this.rows.get(id)!;
    this.rows.set(id, { ...row, title, updated_at: new Date() });
    return Promise.resolve();
  }
  softDelete(_q: Queryable, id: string, at: Date): Promise<void> {
    const row = this.rows.get(id)!;
    this.rows.set(id, { ...row, deleted_at: at });
    return Promise.resolve();
  }
}

/** In-memory append-only VersionsRepo. */
export class FakeVersions {
  readonly rows: VersionRow[] = [];

  insert(
    _q: Queryable,
    row: {
      documentId: string;
      version: number;
      objectKey: string;
      contentSha256: Buffer;
      sizeBytes: number;
      mime: string;
      createdBy: string;
      ocrIndexed?: boolean;
    },
  ): Promise<void> {
    if (this.rows.some((r) => r.document_id === row.documentId && r.version === row.version)) {
      return Promise.reject(
        Object.assign(new Error('duplicate key'), {
          code: '23505',
          constraint: 'document_versions_document_id_version_key',
        }),
      );
    }
    this.rows.push({
      id: randomUUID(),
      document_id: row.documentId,
      version: row.version,
      object_key: row.objectKey,
      content_sha256: row.contentSha256,
      size_bytes: String(row.sizeBytes),
      mime: row.mime,
      ocr_indexed: row.ocrIndexed ?? false,
      created_by: row.createdBy,
      created_at: new Date(),
    });
    return Promise.resolve();
  }
  listByDocument(_q: Queryable | Db, documentId: string): Promise<VersionRow[]> {
    return Promise.resolve(
      this.rows.filter((r) => r.document_id === documentId).sort((a, b) => a.version - b.version),
    );
  }
  getByVersion(
    _q: Queryable | Db,
    documentId: string,
    version: number,
  ): Promise<VersionRow | null> {
    return Promise.resolve(
      this.rows.find((r) => r.document_id === documentId && r.version === version) ?? null,
    );
  }
}

/** In-memory TemplatesRepo (rows are seeded via publishSourceToFakes). */
export class FakeTemplates {
  readonly rows = new Map<string, TemplateRow>();

  findActive(
    _q: Queryable | Db,
    docType: TemplateRow['doc_type'],
    state: TemplateRow['state'],
  ): Promise<TemplateRow | null> {
    return Promise.resolve(
      [...this.rows.values()].find(
        (r) => r.doc_type === docType && r.state === state && r.active && r.deleted_at === null,
      ) ?? null,
    );
  }
  findById(_q: Queryable | Db, id: string): Promise<TemplateRow | null> {
    const row = this.rows.get(id);
    return Promise.resolve(row && row.deleted_at === null ? row : null);
  }
  listActiveByState(_q: Queryable | Db, state: TemplateRow['state']): Promise<TemplateRow[]> {
    return Promise.resolve(
      [...this.rows.values()].filter((r) => r.state === state && r.active && r.deleted_at === null),
    );
  }
}

/** SearchIndexer over a random key (constructor wants the full config shape). */
export function buildIndexer(): SearchIndexer {
  return new SearchIndexer({ searchIndexKey: randomBytes(32) } as unknown as DocumentsConfig);
}

/**
 * In-memory SearchTokensRepo. Holds a FakeDocuments reference so
 * findMatchingAll can apply the same user/deleted filters as the SQL join.
 */
export class FakeSearchTokens {
  private readonly byDocument = new Map<string, Set<string>>();

  constructor(private readonly documents: FakeDocuments) {}

  replaceForDocument(_q: Queryable, documentId: string, tokens: Buffer[]): Promise<void> {
    this.byDocument.set(documentId, new Set(tokens.map((t) => t.toString('hex'))));
    return Promise.resolve();
  }

  findMatchingAll(_q: Queryable | Db, userId: string, tokens: Buffer[]): Promise<string[]> {
    if (tokens.length === 0) {
      return Promise.resolve([]);
    }
    const wanted = tokens.map((t) => t.toString('hex'));
    const out: string[] = [];
    for (const [documentId, indexed] of this.byDocument) {
      const doc = this.documents.rows.get(documentId);
      if (!doc || doc.user_id !== userId || doc.deleted_at !== null) {
        continue;
      }
      if (wanted.every((t) => indexed.has(t))) {
        out.push(documentId);
      }
    }
    return Promise.resolve(out.sort());
  }
}

/** Publish a template source into the fake store + repo (bypassing the CLI). */
export async function publishSourceToFakes(
  source: TemplateSource,
  store: ObjectStore,
  templates: FakeTemplates,
  options: { active?: boolean } = {},
): Promise<TemplateRow> {
  const bytes = Buffer.from(JSON.stringify(source), 'utf8');
  const key = templateObjectKey(source.docType, source.state, source.version);
  await store.put(key, bytes);
  const row: TemplateRow = {
    id: randomUUID(),
    doc_type: source.docType,
    state: source.state,
    version: source.version,
    body_ref: key,
    body_sha256: createHash('sha256').update(bytes).digest(),
    legal_review_by: source.legalReview.by,
    legal_review_at: new Date(source.legalReview.at),
    execution_requirements: source.executionRequirements,
    variables: source.variables,
    active: options.active ?? true,
    created_at: new Date(),
    deleted_at: null,
  };
  templates.rows.set(row.id, row);
  return row;
}

/** A compact will-like template exercising conditionals + every variable kind. */
export function sampleSource(overrides: Partial<TemplateSource> = {}): TemplateSource {
  return {
    docType: 'will',
    state: 'CA',
    version: 1,
    title: 'Last Will and Testament',
    legalReview: { by: 'Test Counsel', at: '2026-07-01T00:00:00.000Z' },
    activate: true,
    executionRequirements: { witnesses: 2, notarization: false, selfProvingAffidavit: false },
    variables: [
      { name: 'testatorName', kind: 'text', required: true, maxLength: 200 },
      { name: 'executorName', kind: 'text', required: true, maxLength: 200 },
      { name: 'hasMinorChildren', kind: 'boolean', required: true },
      { name: 'guardianName', kind: 'text', required: false, maxLength: 200 },
      { name: 'signedOn', kind: 'date', required: true },
      { name: 'maritalStatus', kind: 'enum', required: true, options: ['single', 'married'] },
    ],
    body: [
      {
        heading: 'Declaration',
        text: 'I, {{testatorName}} ({{maritalStatus}}), declare this my will on {{signedOn}}.',
      },
      { heading: 'Executor', text: 'I appoint {{executorName}} as executor.' },
      {
        when: 'hasMinorChildren',
        heading: 'Guardianship',
        text: 'I nominate {{guardianName}} as guardian.',
      },
      { when: { not: 'hasMinorChildren' }, text: 'I have no minor children.' },
    ],
    ...overrides,
  };
}

/**
 * A minimal well-formed-enough PDF fixture: sniffs as application/pdf and
 * carries its "scanned" text as literal bytes, which is exactly what StubOcr
 * extracts. Optionally embeds an arbitrary byte payload (e.g. EICAR).
 */
export function pdfFixture(text: string, extra: Buffer = Buffer.alloc(0)): Buffer {
  return Buffer.concat([
    Buffer.from(`%PDF-1.4\n1 0 obj\n<< >>\nstream\n${text}\nendstream\n`, 'latin1'),
    extra,
    Buffer.from('\n%%EOF\n', 'latin1'),
  ]);
}

export function sampleVariables(): Record<string, string | boolean> {
  return {
    testatorName: 'Alexandra Example',
    executorName: 'Jordan Executor',
    hasMinorChildren: false,
    signedOn: '2026-07-23',
    maritalStatus: 'married',
  };
}
