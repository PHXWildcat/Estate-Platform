import { randomUUID } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  GoneException,
  NotFoundException,
  ServiceUnavailableException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { AuditEventSchema } from '@estate/contracts';
import { DocumentsAuthz } from '../src/authz.service';
import { DocumentsService } from '../src/documents.service';
import { EICAR_TEST_STRING, StubScanner, type MalwareScanner } from '../src/malware-scanner';
import { StubOcr, type OcrEngine } from '../src/ocr';
import { TemplateEngine } from '../src/template-engine';
import {
  buildCipher,
  buildIndexer,
  capturingEvents,
  fakeDb,
  FakeDocuments,
  FakeSearchTokens,
  FakeTemplates,
  FakeVersions,
  MemoryDeks,
  MemoryObjectStore,
  pdfFixture,
  publishSourceToFakes,
  sampleSource,
  sampleVariables,
} from './support';
import type { InMemoryAuditProducer } from '../src/audit-producer';
import type { UploadDocumentInput } from '../src/schemas';
import type { TemplateRow } from '../src/templates.repo';
import type { SettlementEvidenceAuthority } from '@estate/settlement-client';

const OWNER = randomUUID();
const STRANGER = randomUUID();

interface Harness {
  service: DocumentsService;
  docs: FakeDocuments;
  versions: FakeVersions;
  templates: FakeTemplates;
  store: MemoryObjectStore;
  deks: MemoryDeks;
  producer: InMemoryAuditProducer;
  template: TemplateRow;
}

interface HarnessOptions {
  scanner?: MalwareScanner;
  ocr?: OcrEngine;
  settlement?: SettlementEvidenceAuthority;
}

/** Default: settlement refuses everything (the client's fail-closed posture). */
const refusingSettlement: SettlementEvidenceAuthority = {
  checkEvidenceRead: () => Promise.resolve({ allowed: false }),
};

async function build(options: HarnessOptions = {}): Promise<Harness> {
  const docs = new FakeDocuments();
  const versions = new FakeVersions();
  const templates = new FakeTemplates();
  const store = new MemoryObjectStore();
  const deks = new MemoryDeks();
  const { events, producer } = capturingEvents();
  const template = await publishSourceToFakes(sampleSource(), store, templates);
  const service = new DocumentsService(
    fakeDb(),
    docs,
    versions,
    templates,
    new TemplateEngine(store),
    buildCipher(deks, events),
    new DocumentsAuthz(new PolicyDecisionPoint(loadBundledPolicies())),
    events,
    buildIndexer(),
    new FakeSearchTokens(docs),
    deks,
    store,
    options.scanner ?? new StubScanner(),
    options.ocr ?? new StubOcr(),
    options.settlement ?? refusingSettlement,
  );
  return { service, docs, versions, templates, store, deks, producer, template };
}

async function generate(h: Harness): Promise<string> {
  const result = await h.service.generate(OWNER, {
    docType: 'will',
    state: 'CA',
    variables: sampleVariables(),
  });
  return result.documentId;
}

describe('generation pipeline', () => {
  it('generates: metadata row, version row, encrypted blob, audit + domain events', async () => {
    const h = await build();
    const result = await h.service.generate(OWNER, {
      docType: 'will',
      state: 'CA',
      variables: sampleVariables(),
    });
    expect(result.version).toBe(1);
    expect(result.executionStatus).toBe('generated');

    const row = h.docs.rows.get(result.documentId)!;
    expect(row.user_id).toBe(OWNER);
    expect(row.template_id).toBe(h.template.id);
    expect(row.title).toBe('Last Will and Testament');

    const versionRow = h.versions.rows[0]!;
    expect(versionRow.version).toBe(1);
    expect(versionRow.content_sha256.toString('hex')).toBe(result.contentSha256);

    // The stored blob is ciphertext: it never contains intake plaintext.
    const blob = h.store.objects.get(versionRow.object_key)!;
    expect(blob.includes(Buffer.from('Alexandra Example'))).toBe(false);
    expect(blob.includes(Buffer.from('<!doctype html>'))).toBe(false);

    const auditActions = h.producer.messages
      .filter((m) => m.topic === 'estate.audit.events.v1')
      .map((m) => (JSON.parse(m.value) as { action: string }).action);
    expect(auditActions).toContain('document.generated');
    const domain = h.producer.messages.filter((m) => m.topic === 'estate.document.events.v1');
    expect(domain).toHaveLength(1);
    expect((JSON.parse(domain[0]!.value) as { type: string }).type).toBe(
      'document.version.created',
    );
  });

  it('round-trips content: decrypt returns the exact rendered HTML, audited', async () => {
    const h = await build();
    const documentId = await generate(h);
    const content = await h.service.getContent(OWNER, documentId, 1);
    expect(content.mime).toBe('text/html');
    expect(content.content).toContain('I, Alexandra Example (married)');
    expect(content.content).toContain('<!doctype html>');
    const actions = h.producer.messages
      .filter((m) => m.topic === 'estate.audit.events.v1')
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action);
    expect(actions).toContain('crypto.field.decrypted');
    expect(actions).toContain('document.content.viewed');
  });

  it('404s when no active template matches (docType, state)', async () => {
    const h = await build();
    await expect(
      h.service.generate(OWNER, { docType: 'will', state: 'TX', variables: sampleVariables() }),
    ).rejects.toThrow(NotFoundException);
  });

  it('rejects a pinned template that is inactive or mismatched', async () => {
    const h = await build();
    h.templates.rows.get(h.template.id)!.active = false;
    await expect(
      h.service.generate(OWNER, {
        docType: 'will',
        state: 'CA',
        templateId: h.template.id,
        variables: sampleVariables(),
      }),
    ).rejects.toThrow(NotFoundException);
  });

  it('422s intake payloads the template schema rejects — nothing is stored', async () => {
    const h = await build();
    for (const variables of [
      {},
      { ...sampleVariables(), smuggled: 'x' },
      { ...sampleVariables(), maritalStatus: 'other' },
    ]) {
      await expect(
        h.service.generate(OWNER, { docType: 'will', state: 'CA', variables }),
      ).rejects.toThrow(UnprocessableEntityException);
    }
    expect(h.docs.rows.size).toBe(0);
    expect(h.store.objects.size).toBe(1); // only the template body itself
  });
});

describe('versioning', () => {
  it('creates version 2 and resets status to generated', async () => {
    const h = await build();
    const documentId = await generate(h);
    const result = await h.service.newVersion(OWNER, documentId, {
      variables: { ...sampleVariables(), executorName: 'New Executor' },
    });
    expect(result.version).toBe(2);
    expect(h.docs.rows.get(documentId)!.current_version).toBe(2);
    expect(h.versions.rows).toHaveLength(2);
    const v2 = await h.service.getContent(OWNER, documentId, 2);
    expect(v2.content).toContain('New Executor');
    const v1 = await h.service.getContent(OWNER, documentId, 1);
    expect(v1.content).toContain('Jordan Executor');
  });

  it('enforces If-Match against current_version', async () => {
    const h = await build();
    const documentId = await generate(h);
    await expect(
      h.service.newVersion(OWNER, documentId, { variables: sampleVariables() }, 99),
    ).rejects.toThrow(ConflictException);
  });

  it('a stale If-Match 409s BEFORE intake validation (no 422 for stale writers)', async () => {
    const h = await build();
    const documentId = await generate(h);
    // Deliberately invalid intake: the concurrency conflict must win.
    await expect(h.service.newVersion(OWNER, documentId, { variables: {} }, 99)).rejects.toThrow(
      ConflictException,
    );
  });

  it('refuses regeneration once signing has started', async () => {
    const h = await build();
    const documentId = await generate(h);
    await h.service.transitionStatus(OWNER, documentId, { status: 'signed' });
    await expect(
      h.service.newVersion(OWNER, documentId, { variables: sampleVariables() }),
    ).rejects.toThrow(ConflictException);
  });

  it('refuses regeneration when the document DEK is crypto-shredded (never re-mints)', async () => {
    const h = await build();
    const documentId = await generate(h);
    const dekId = h.docs.rows.get(documentId)!.dek_id;
    await h.deks.markDestroyed(dekId, new Date());
    await expect(
      h.service.newVersion(OWNER, documentId, { variables: sampleVariables() }),
    ).rejects.toThrow(GoneException);
    // The shred invariant holds: no fresh active DEK was minted for the document.
    expect(await h.deks.findActiveByUser(documentId)).toBeNull();
    expect(h.docs.rows.get(documentId)!.current_version).toBe(1);
  });
});

describe('execution-status tracking', () => {
  it('walks the template ladder: generated → signed → witnessed → executed', async () => {
    const h = await build();
    const documentId = await generate(h);
    await h.service.transitionStatus(OWNER, documentId, { status: 'signed' });
    await h.service.transitionStatus(OWNER, documentId, { status: 'witnessed' });
    const dto = await h.service.transitionStatus(OWNER, documentId, {
      status: 'executed',
      executedAt: '2026-07-23',
    });
    expect(dto.executionStatus).toBe('executed');
    expect(dto.executedAt).toBe('2026-07-23');
  });

  it('409s skipped required steps; 422s executedAt misuse', async () => {
    const h = await build();
    const documentId = await generate(h);
    await h.service.transitionStatus(OWNER, documentId, { status: 'signed' });
    // CA will requires witnesses: signed → executed skips a required step.
    await expect(
      h.service.transitionStatus(OWNER, documentId, {
        status: 'executed',
        executedAt: '2026-07-23',
      }),
    ).rejects.toThrow(ConflictException);
    await expect(
      h.service.transitionStatus(OWNER, documentId, {
        status: 'witnessed',
        executedAt: '2026-07-23',
      }),
    ).rejects.toThrow(UnprocessableEntityException);
    await expect(
      h.service.transitionStatus(OWNER, documentId, { status: 'executed' }),
    ).rejects.toThrow(UnprocessableEntityException);
  });

  it('emits status-change audit + domain events with from/to', async () => {
    const h = await build();
    const documentId = await generate(h);
    await h.service.transitionStatus(OWNER, documentId, { status: 'signed' });
    const audit = h.producer.messages
      .filter((m) => m.topic === 'estate.audit.events.v1')
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
      .find((e) => e.action === 'document.status.changed')!;
    expect(audit.detail).toEqual({ from: 'generated', to: 'signed' });
  });

  it('fails CLOSED on the execution ladder when a generated doc template is unavailable', async () => {
    // Old behavior dropped to DEFAULT_REQUIREMENTS (no witnesses/notary) and
    // let signed→executed skip state-mandated formalities. Now the transition
    // is refused entirely rather than trusting the weakest ladder.
    const h = await build();
    const documentId = await generate(h);
    // Soft-delete the template out from under the already-generated document.
    h.templates.rows.get(h.template.id)!.deleted_at = new Date();
    await expect(
      h.service.transitionStatus(OWNER, documentId, { status: 'signed' }),
    ).rejects.toThrow(ConflictException);
  });
});

describe('deletion and legal hold', () => {
  it('soft-deletes; content and metadata stop being served', async () => {
    const h = await build();
    const documentId = await generate(h);
    await h.service.softDelete(OWNER, documentId);
    await expect(h.service.get(OWNER, documentId)).rejects.toThrow(NotFoundException);
    await expect(h.service.getContent(OWNER, documentId, 1)).rejects.toThrow(NotFoundException);
    expect(await h.service.list(OWNER)).toEqual([]);
  });

  it('legal hold blocks deletion with 409', async () => {
    const h = await build();
    const documentId = await generate(h);
    h.docs.rows.get(documentId)!.legal_hold = true;
    await expect(h.service.softDelete(OWNER, documentId)).rejects.toThrow(ConflictException);
    expect((await h.service.get(OWNER, documentId)).legalHold).toBe(true);
  });
});

describe('authorization (deny-by-default PEP)', () => {
  it('denies non-owners every action and filters lists', async () => {
    const h = await build();
    const documentId = await generate(h);
    await expect(h.service.get(STRANGER, documentId)).rejects.toThrow(ForbiddenException);
    await expect(h.service.getContent(STRANGER, documentId, 1)).rejects.toThrow(ForbiddenException);
    await expect(
      h.service.newVersion(STRANGER, documentId, { variables: sampleVariables() }),
    ).rejects.toThrow(ForbiddenException);
    await expect(
      h.service.transitionStatus(STRANGER, documentId, { status: 'signed' }),
    ).rejects.toThrow(ForbiddenException);
    await expect(h.service.softDelete(STRANGER, documentId)).rejects.toThrow(ForbiddenException);
    expect(await h.service.list(STRANGER)).toEqual([]);
  });
});

describe('upload pipeline', () => {
  const CONTENT_TEXT = 'Deed for the lake house recorded in Marlow County';

  function uploadInput(overrides: Partial<UploadDocumentInput> = {}): UploadDocumentInput {
    return {
      kind: 'property',
      title: 'Lake house deed',
      mime: 'application/pdf',
      contentBase64: pdfFixture(CONTENT_TEXT).toString('base64'),
      ...overrides,
    };
  }

  it('ingests a clean PDF: encrypted blob + OCR artifact, draft status, indexed', async () => {
    const h = await build();
    const result = await h.service.upload(OWNER, uploadInput());
    expect(result.version).toBe(1);
    expect(result.executionStatus).toBe('draft');
    expect(result.ocrIndexed).toBe(true);

    const row = h.docs.rows.get(result.documentId)!;
    expect(row.source).toBe('uploaded');
    expect(row.doc_type).toBe('property');
    expect(row.template_id).toBeNull();

    const versionRow = h.versions.rows[0]!;
    expect(versionRow.mime).toBe('application/pdf');
    expect(versionRow.ocr_indexed).toBe(true);

    // Blob and OCR artifact are ciphertext: no plaintext markers anywhere.
    const blob = h.store.objects.get(versionRow.object_key)!;
    expect(blob.includes(Buffer.from('%PDF'))).toBe(false);
    expect(blob.includes(Buffer.from('Marlow'))).toBe(false);
    const ocrArtifact = h.store.objects.get(`documents/${result.documentId}/v1-ocr`)!;
    expect(ocrArtifact).toBeInstanceOf(Buffer);
    expect(ocrArtifact.includes(Buffer.from('Marlow'))).toBe(false);

    const actions = h.producer.messages
      .filter((m) => m.topic === 'estate.audit.events.v1')
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action);
    expect(actions).toContain('document.uploaded');
    expect(actions).toContain('document.ocr.indexed');
  });

  it('round-trips binary content as base64 with the stored sha', async () => {
    const h = await build();
    const bytes = pdfFixture(CONTENT_TEXT);
    const { documentId, contentSha256 } = await h.service.upload(OWNER, uploadInput());
    const content = await h.service.getContent(OWNER, documentId, 1);
    expect(content.encoding).toBe('base64');
    expect(Buffer.from(content.content, 'base64').equals(bytes)).toBe(true);
    expect(content.contentSha256).toBe(contentSha256);
  });

  it('rejects infected uploads: 422, audited, and NOTHING is ever stored', async () => {
    const h = await build();
    await expect(
      h.service.upload(
        OWNER,
        uploadInput({
          contentBase64: pdfFixture(CONTENT_TEXT, Buffer.from(EICAR_TEST_STRING)).toString(
            'base64',
          ),
        }),
      ),
    ).rejects.toThrow(UnprocessableEntityException);
    expect(h.docs.rows.size).toBe(0);
    expect(h.versions.rows).toHaveLength(0);
    expect(h.store.objects.size).toBe(1); // the template body only

    const rejection = h.producer.messages
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
      .find((e) => e.action === 'document.scan.rejected')!;
    expect(rejection.detail['reason']).toBe('infected');
    expect(rejection.detail['signature']).toBe('Eicar-Signature');
    expect(rejection.resourceId).toBeNull();
  });

  it('fails CLOSED when the scanner is unavailable (503, audited, not stored)', async () => {
    const failing: MalwareScanner = {
      scan: () => Promise.reject(new Error('connection refused')),
    };
    const h = await build({ scanner: failing });
    await expect(h.service.upload(OWNER, uploadInput())).rejects.toThrow(
      ServiceUnavailableException,
    );
    expect(h.docs.rows.size).toBe(0);
    const rejection = h.producer.messages
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
      .find((e) => e.action === 'document.scan.rejected')!;
    expect(rejection.detail['reason']).toBe('scanner_error');
  });

  it('admits ONLY a clean verdict — an unknown verdict is rejected (fail closed)', async () => {
    // A future/unexpected verdict variant must never fall through to storage.
    const weird: MalwareScanner = {
      scan: () => Promise.resolve({ verdict: 'suspicious' } as never),
    };
    const h = await build({ scanner: weird });
    await expect(h.service.upload(OWNER, uploadInput())).rejects.toThrow(
      UnprocessableEntityException,
    );
    expect(h.docs.rows.size).toBe(0);
    expect(h.versions.rows).toHaveLength(0);
  });

  it('re-clamps a raw scanner signature at the audit egress', async () => {
    // A non-conforming (un-sanitized) signature would fail the audit schema
    // gate and abort the emit; re-clamping at egress makes it emit cleanly and
    // keeps third-party text out of the append-only store regardless of adapter.
    const dirty: MalwareScanner = {
      scan: () => Promise.resolve({ verdict: 'infected', signature: 'Bad Name <script> ünïcode' }),
    };
    const h = await build({ scanner: dirty });
    await expect(h.service.upload(OWNER, uploadInput())).rejects.toThrow(
      UnprocessableEntityException,
    );
    const rejection = h.producer.messages
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
      .find((e) => e.action === 'document.scan.rejected')!;
    expect(String(rejection.detail['signature'])).toMatch(/^[A-Za-z0-9_.:-]{1,128}$/);
    expect(String(rejection.detail['signature'])).not.toContain(' ');
  });

  it('rejects undeclared/mismatched/oversized content before scanning', async () => {
    const h = await build();
    // Declared pdf, bytes are PNG-ish: polyglot mislabeling refused.
    await expect(
      h.service.upload(
        OWNER,
        uploadInput({
          contentBase64: Buffer.concat([
            Buffer.from('89504e470d0a1a0a', 'hex'),
            Buffer.from('not a pdf'),
          ]).toString('base64'),
        }),
      ),
    ).rejects.toThrow(UnprocessableEntityException);
    // HTML is never accepted, whatever it claims to be.
    await expect(
      h.service.upload(
        OWNER,
        uploadInput({
          mime: 'text/html',
          contentBase64: Buffer.from('<script>alert(1)</script>').toString('base64'),
        }),
      ),
    ).rejects.toThrow(UnprocessableEntityException);
    expect(h.docs.rows.size).toBe(0);
  });

  it('OCR failure is non-fatal: stored un-indexed, searchable by title', async () => {
    const failingOcr: OcrEngine = {
      extractText: () => Promise.reject(new Error('ocr exploded')),
    };
    const h = await build({ ocr: failingOcr });
    const result = await h.service.upload(OWNER, uploadInput());
    expect(result.ocrIndexed).toBe(false);
    expect(h.versions.rows[0]!.ocr_indexed).toBe(false);
    expect(h.store.objects.has(`documents/${result.documentId}/v1-ocr`)).toBe(false);
    const byTitle = await h.service.search(OWNER, 'deed lake');
    expect(byTitle.map((d) => d.documentId)).toEqual([result.documentId]);
  });
});

describe('encrypted search', () => {
  it('finds documents by OCR text and title (AND semantics), never across users', async () => {
    const h = await build();
    const { documentId } = await h.service.upload(OWNER, {
      kind: 'property',
      title: 'Lake house deed',
      mime: 'application/pdf',
      contentBase64: pdfFixture('recorded in Marlow County').toString('base64'),
    });

    expect((await h.service.search(OWNER, 'marlow county')).map((d) => d.documentId)).toEqual([
      documentId,
    ]);
    expect(await h.service.search(OWNER, 'marlow nonexistent')).toEqual([]);
    // Same query, different principal: per-user keying yields nothing.
    expect(await h.service.search(STRANGER, 'marlow county')).toEqual([]);
  });

  it('indexes generated documents and re-indexes on new versions', async () => {
    const h = await build();
    const { documentId } = await h.service.generate(OWNER, {
      docType: 'will',
      state: 'CA',
      variables: sampleVariables(),
    });
    expect((await h.service.search(OWNER, 'jordan executor')).map((d) => d.documentId)).toEqual([
      documentId,
    ]);
    await h.service.newVersion(OWNER, documentId, {
      variables: { ...sampleVariables(), executorName: 'Robin Replacement' },
    });
    expect(await h.service.search(OWNER, 'jordan')).toEqual([]);
    expect((await h.service.search(OWNER, 'robin')).map((d) => d.documentId)).toEqual([documentId]);
  });

  it('drops soft-deleted documents from results', async () => {
    const h = await build();
    const { documentId } = await h.service.generate(OWNER, {
      docType: 'will',
      state: 'CA',
      variables: sampleVariables(),
    });
    await h.service.softDelete(OWNER, documentId);
    expect(await h.service.search(OWNER, 'jordan executor')).toEqual([]);
  });
});

describe('crypto-shredding', () => {
  it('410s content whose document DEK was destroyed; metadata survives', async () => {
    const h = await build();
    const documentId = await generate(h);
    const dekId = h.docs.rows.get(documentId)!.dek_id;
    await h.deks.markDestroyed(dekId, new Date());
    await expect(h.service.getContent(OWNER, documentId, 1)).rejects.toThrow(GoneException);
    expect((await h.service.get(OWNER, documentId)).documentId).toBe(documentId);
  });
});

describe('audit PII firewall', () => {
  it('no message on any topic ever carries intake plaintext', async () => {
    const h = await build();
    const documentId = await generate(h);
    await h.service.getContent(OWNER, documentId, 1);
    await h.service.transitionStatus(OWNER, documentId, { status: 'signed' });
    for (const message of h.producer.messages) {
      expect(message.value).not.toContain('Alexandra');
      expect(message.value).not.toContain('Jordan');
      expect(message.value).not.toContain('Last Will');
    }
  });
});

describe('evidence reads (M7 settlement authority)', () => {
  const OPERATOR = randomUUID();
  const CASE_ID = randomUUID();

  function allowingSettlement(ownerUserId: string): SettlementEvidenceAuthority {
    return {
      checkEvidenceRead: () => Promise.resolve({ allowed: true, caseId: CASE_ID, ownerUserId }),
    };
  }

  it('decrypts for an operator when settlement grants authority, audited with onBehalfOf', async () => {
    const h = await build({ settlement: allowingSettlement(OWNER) });
    const documentId = await generate(h);
    const content = await h.service.getEvidenceContent(OPERATOR, 'op-token', documentId, 1);
    expect(content.content).toContain('<!doctype html>');
    const audit = h.producer.messages
      .filter((m) => m.topic === 'estate.audit.events.v1')
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
      .find((e) => e.action === 'document.evidence.accessed')!;
    expect(audit.actorId).toBe(OPERATOR);
    expect(audit.onBehalfOf).toBe(OWNER);
    expect(audit.detail).toEqual({ version: 1, caseId: CASE_ID });
  });

  it('404s when settlement refuses (fail closed, no oracle)', async () => {
    const h = await build(); // refusingSettlement default
    const documentId = await generate(h);
    await expect(h.service.getEvidenceContent(OPERATOR, 'op-token', documentId, 1)).rejects.toThrow(
      NotFoundException,
    );
  });

  it("404s when the document's real owner differs from the registered uploader", async () => {
    // A reporter registering someone ELSE's document id as evidence must not
    // hand an operator a decryption of it: settlement's recorded uploader is
    // cross-checked against the row's actual owner.
    const h = await build({ settlement: allowingSettlement(STRANGER) });
    const documentId = await generate(h); // owned by OWNER, not STRANGER
    await expect(h.service.getEvidenceContent(OPERATOR, 'op-token', documentId, 1)).rejects.toThrow(
      NotFoundException,
    );
    const actions = h.producer.messages
      .filter((m) => m.topic === 'estate.audit.events.v1')
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action);
    expect(actions).not.toContain('document.evidence.accessed');
    expect(actions).not.toContain('crypto.field.decrypted');
  });

  it('404s an unknown document even with an allowing authority', async () => {
    const h = await build({ settlement: allowingSettlement(OWNER) });
    await expect(
      h.service.getEvidenceContent(OPERATOR, 'op-token', randomUUID(), 1),
    ).rejects.toThrow(NotFoundException);
  });
});
