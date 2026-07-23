import { randomUUID } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  GoneException,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { AuditEventSchema } from '@estate/contracts';
import { DocumentsAuthz } from '../src/authz.service';
import { DocumentsService } from '../src/documents.service';
import { TemplateEngine } from '../src/template-engine';
import {
  buildCipher,
  capturingEvents,
  fakeDb,
  FakeDocuments,
  FakeTemplates,
  FakeVersions,
  MemoryDeks,
  MemoryObjectStore,
  publishSourceToFakes,
  sampleSource,
  sampleVariables,
} from './support';
import type { InMemoryAuditProducer } from '../src/audit-producer';
import type { TemplateRow } from '../src/templates.repo';

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

async function build(): Promise<Harness> {
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
    store,
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

  it('refuses regeneration once signing has started', async () => {
    const h = await build();
    const documentId = await generate(h);
    await h.service.transitionStatus(OWNER, documentId, { status: 'signed' });
    await expect(
      h.service.newVersion(OWNER, documentId, { variables: sampleVariables() }),
    ).rejects.toThrow(ConflictException);
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
