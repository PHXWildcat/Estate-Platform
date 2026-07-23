import { createHash, randomUUID } from 'node:crypto';
import {
  ConflictException,
  GoneException,
  Inject,
  Injectable,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import type { ExecutionStatus } from '@estate/contracts';
import { DekDestroyedError } from '@estate/crypto';
import { ContentCipher } from './content-cipher';
import { Db, type Queryable } from './db';
import { DocumentsAuthz, documentResource } from './authz.service';
import { DocumentsRepo, type DocumentRow } from './documents.repo';
import { EventsService } from './events.service';
import { allowsNewVersion, isTransitionAllowed } from './execution-status';
import { OBJECT_STORE } from './di-tokens';
import type { ObjectStore } from './object-store';
import { RenderError, renderDocument } from './renderer';
import { TemplateEngine } from './template-engine';
import {
  ExecutionRequirementsSchema,
  intakeSchemaFor,
  type ExecutionRequirements,
  type TemplateSource,
} from './template-model';
import { TemplatesRepo, type TemplateRow } from './templates.repo';
import { VersionsRepo, type VersionRow } from './versions.repo';
import type { GenerateDocumentInput, NewVersionInput, StatusTransitionInput } from './schemas';

export interface DocumentDto {
  documentId: string;
  docType: string;
  source: string;
  title: string;
  currentVersion: number;
  executionStatus: ExecutionStatus;
  executedAt: string | null;
  legalHold: boolean;
  sealed: boolean;
  templateId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface VersionDto {
  version: number;
  contentSha256: string;
  sizeBytes: number;
  mime: string;
  createdBy: string;
  createdAt: string;
}

export interface GenerateResult {
  documentId: string;
  version: number;
  contentSha256: string;
  executionStatus: ExecutionStatus;
}

export interface ContentDto {
  documentId: string;
  version: number;
  mime: string;
  contentSha256: string;
  content: string;
}

/** Execution requirements applied when a document has no template (uploads). */
const DEFAULT_REQUIREMENTS: ExecutionRequirements = {
  witnesses: 0,
  notarization: false,
  selfProvingAffidavit: false,
};

/** Object key for a version's encrypted content blob. */
export function contentObjectKey(documentId: string, version: number, shaHex: string): string {
  return `documents/${documentId}/v${version}-${shaHex}`;
}

@Injectable()
export class DocumentsService {
  constructor(
    private readonly db: Db,
    private readonly documents: DocumentsRepo,
    private readonly versions: VersionsRepo,
    private readonly templates: TemplatesRepo,
    private readonly engine: TemplateEngine,
    private readonly cipher: ContentCipher,
    private readonly authz: DocumentsAuthz,
    private readonly events: EventsService,
    @Inject(OBJECT_STORE) private readonly store: ObjectStore,
  ) {}

  // ------------------------------------------------------------------ commands

  /**
   * The generation pipeline (docs/01 §2.4). Step-up gating happens at the
   * controller (StepUpGuard — document generation is a mandatory step-up
   * action per docs/01 §5); this method resolves the template, validates the
   * intake payload against the template's typed declaration, renders
   * deterministically, encrypts under a fresh per-document DEK, writes the
   * blob, and commits metadata + version row atomically.
   */
  async generate(actor: string, input: GenerateDocumentInput): Promise<GenerateResult> {
    const documentId = randomUUID();
    this.authz.assertCan(actor, 'create', documentResource(documentId, actor));
    const row = input.templateId
      ? await this.templates.findById(this.db, input.templateId)
      : await this.templates.findActive(this.db, input.docType, input.state);
    if (!row || !row.active || row.doc_type !== input.docType || row.state !== input.state) {
      throw new NotFoundException({ error: 'template_not_found' });
    }
    const source = await this.engine.load(row);
    const rendered = this.render(source, input.variables);
    // Encrypt + store OUTSIDE the transaction (KMS/object-store latency stays
    // out of the lock window). If the transaction below fails, the orphaned
    // blob is unreadable ciphertext keyed by a document id that never came to
    // exist — garbage, not a leak.
    const dekId = await this.cipher.getOrCreateDek(documentId);
    const { ciphertext } = await this.cipher.encrypt({
      documentId,
      ownerUserId: actor,
      version: 1,
      sha256Hex: rendered.shaHex,
      content: rendered.bytes,
    });
    const objectKey = contentObjectKey(documentId, 1, rendered.shaHex);
    await this.store.put(objectKey, ciphertext);
    await this.db.withTransaction(actor, async (tx) => {
      await this.documents.insert(tx, {
        id: documentId,
        userId: actor,
        docType: row.doc_type,
        templateId: row.id,
        source: 'generated',
        title: input.title ?? source.title,
        executionStatus: 'generated',
        dekId,
      });
      await this.versions.insert(tx, {
        documentId,
        version: 1,
        objectKey,
        contentSha256: rendered.sha,
        sizeBytes: rendered.bytes.length,
        mime: 'text/html',
        createdBy: actor,
      });
    });
    await this.events.documentGenerated(actor, documentId, {
      docType: row.doc_type,
      state: row.state,
      templateId: row.id,
      templateVersion: row.version,
    });
    await this.events.versionCreated({
      actorId: actor,
      documentId,
      version: 1,
      docType: row.doc_type,
      source: 'generated',
    });
    return {
      documentId,
      version: 1,
      contentSha256: rendered.shaHex,
      executionStatus: 'generated',
    };
  }

  /**
   * Regenerate content as the next version. Refused once signing has started
   * (allowsNewVersion): a signed/executed instrument's content is a legal
   * record — revoke or supersede first, then generate fresh.
   */
  async newVersion(
    actor: string,
    documentId: string,
    input: NewVersionInput,
    ifMatch?: number,
  ): Promise<GenerateResult> {
    const doc = await this.requireLive(documentId);
    this.authz.assertCan(actor, 'update', documentResource(documentId, doc.user_id));
    if (!allowsNewVersion(doc.execution_status)) {
      throw new ConflictException({ error: 'invalid_status' });
    }
    const row = await this.resolveRegenTemplate(doc, input.templateId);
    const source = await this.engine.load(row);
    const rendered = this.render(source, input.variables);
    // The implicit concurrency expectation is the version we read; an
    // explicit If-Match must agree with it, and the locked re-check below
    // makes the expectation authoritative.
    const expectedVersion = ifMatch ?? doc.current_version;
    if (expectedVersion !== doc.current_version) {
      throw new ConflictException({ error: 'version_conflict' });
    }
    const nextVersion = doc.current_version + 1;
    const { ciphertext } = await this.cipher.encrypt({
      documentId,
      ownerUserId: doc.user_id,
      version: nextVersion,
      sha256Hex: rendered.shaHex,
      content: rendered.bytes,
    });
    const objectKey = contentObjectKey(documentId, nextVersion, rendered.shaHex);
    await this.store.put(objectKey, ciphertext);
    await this.db.withTransaction(actor, async (tx) => {
      const locked = await this.lockLive(tx, documentId);
      this.authz.assertCan(actor, 'update', documentResource(documentId, locked.user_id));
      if (!allowsNewVersion(locked.execution_status)) {
        throw new ConflictException({ error: 'invalid_status' });
      }
      if (locked.current_version !== expectedVersion) {
        throw new ConflictException({ error: 'version_conflict' });
      }
      await this.versions.insert(tx, {
        documentId,
        version: nextVersion,
        objectKey,
        contentSha256: rendered.sha,
        sizeBytes: rendered.bytes.length,
        mime: 'text/html',
        createdBy: actor,
      });
      await this.documents.bumpVersion(tx, documentId, nextVersion);
      if (input.title !== undefined) {
        await this.documents.updateTitle(tx, documentId, input.title);
      }
    });
    await this.events.documentVersionCreated(actor, documentId, { version: nextVersion });
    await this.events.versionCreated({
      actorId: actor,
      documentId,
      version: nextVersion,
      docType: doc.doc_type,
      source: doc.source,
    });
    return {
      documentId,
      version: nextVersion,
      contentSha256: rendered.shaHex,
      executionStatus: 'generated',
    };
  }

  /** Attest an execution-status transition (state-machine validated). */
  async transitionStatus(
    actor: string,
    documentId: string,
    input: StatusTransitionInput,
  ): Promise<DocumentDto> {
    if ((input.status === 'executed') !== (input.executedAt !== undefined)) {
      // executedAt accompanies exactly the `executed` attestation.
      throw new UnprocessableEntityException({ error: 'invalid_transition' });
    }
    const updated = await this.db.withTransaction(actor, async (tx) => {
      const locked = await this.lockLive(tx, documentId);
      this.authz.assertCan(actor, 'update', documentResource(documentId, locked.user_id));
      const requirements = await this.requirementsFor(locked);
      if (!isTransitionAllowed(locked.execution_status, input.status, requirements)) {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      await this.documents.updateStatus(tx, documentId, input.status, input.executedAt ?? null);
      return locked;
    });
    await this.events.documentStatusChanged(actor, documentId, {
      from: updated.execution_status,
      to: input.status,
    });
    await this.events.statusChanged({
      actorId: actor,
      documentId,
      from: updated.execution_status,
      to: input.status,
    });
    const fresh = await this.requireLive(documentId);
    return toDto(fresh);
  }

  /**
   * Soft delete (docs/02: no hard deletes; the retention job owns
   * crypto-shredding). Step-up gated at the controller — deletion requests
   * are a mandatory step-up action (docs/01 §5). Legal hold wins over the
   * owner: a held document cannot be deleted by anyone through the API.
   */
  async softDelete(actor: string, documentId: string): Promise<void> {
    await this.db.withTransaction(actor, async (tx) => {
      const locked = await this.lockLive(tx, documentId);
      this.authz.assertCan(actor, 'delete', documentResource(documentId, locked.user_id));
      if (locked.legal_hold) {
        throw new ConflictException({ error: 'legal_hold' });
      }
      await this.documents.softDelete(tx, documentId, new Date());
    });
    await this.events.documentDeleted(actor, documentId);
  }

  // ------------------------------------------------------------------- queries

  async get(actor: string, documentId: string): Promise<DocumentDto> {
    const doc = await this.requireLive(documentId);
    this.authz.assertCan(actor, 'read', documentResource(documentId, doc.user_id));
    return toDto(doc);
  }

  async list(actor: string): Promise<DocumentDto[]> {
    const rows = await this.documents.listLiveByUser(this.db, actor);
    return rows
      .filter((row) => this.authz.can(actor, 'read', documentResource(row.id, row.user_id)))
      .map(toDto);
  }

  async listVersions(actor: string, documentId: string): Promise<VersionDto[]> {
    const doc = await this.requireLive(documentId);
    this.authz.assertCan(actor, 'read', documentResource(documentId, doc.user_id));
    const rows = await this.versions.listByDocument(this.db, documentId);
    return rows.map(toVersionDto);
  }

  /**
   * Decrypt and return a version's content. The AAD binds document, owner,
   * version, and plaintext sha256, so a successful decrypt IS the integrity
   * check — no separate hash comparison is needed. Every decrypt emits
   * `crypto.field.decrypted` (fail-closed) plus the product-level
   * `document.content.viewed`.
   */
  async getContent(actor: string, documentId: string, version: number): Promise<ContentDto> {
    const doc = await this.requireLive(documentId);
    this.authz.assertCan(actor, 'read', documentResource(documentId, doc.user_id));
    const versionRow = await this.versions.getByVersion(this.db, documentId, version);
    if (!versionRow) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const shaHex = versionRow.content_sha256.toString('hex');
    const ciphertext = await this.store.get(versionRow.object_key);
    let content: Buffer;
    try {
      content = await this.cipher.decrypt({
        documentId,
        ownerUserId: doc.user_id,
        version: versionRow.version,
        sha256Hex: shaHex,
        dekId: doc.dek_id,
        ciphertext,
        actorId: actor,
        purpose: 'document_content_read',
      });
    } catch (err) {
      if (err instanceof DekDestroyedError) {
        // Crypto-shredded: the metadata row survives, the meaning does not.
        throw new GoneException({ error: 'content_erased' });
      }
      throw err;
    }
    await this.events.contentViewed(actor, documentId, { version: versionRow.version });
    return {
      documentId,
      version: versionRow.version,
      mime: versionRow.mime,
      contentSha256: shaHex,
      content: content.toString('utf8'),
    };
  }

  // ------------------------------------------------------------------- helpers

  private render(
    source: TemplateSource,
    variables: Record<string, string | boolean>,
  ): { bytes: Buffer; sha: Buffer; shaHex: string } {
    const intake = intakeSchemaFor(source).safeParse(variables);
    if (!intake.success) {
      // Never echo which variable failed how — values are PII.
      throw new UnprocessableEntityException({ error: 'invalid_variables' });
    }
    let html: string;
    try {
      html = renderDocument(source, intake.data);
    } catch (err) {
      if (err instanceof RenderError) {
        throw new UnprocessableEntityException({ error: 'invalid_variables' });
      }
      throw err;
    }
    const bytes = Buffer.from(html, 'utf8');
    const sha = createHash('sha256').update(bytes).digest();
    return { bytes, sha, shaHex: sha.toString('hex') };
  }

  /** Template for a regeneration: the document's own, or an explicit override. */
  private async resolveRegenTemplate(
    doc: DocumentRow,
    overrideTemplateId: string | undefined,
  ): Promise<TemplateRow> {
    if (doc.source !== 'generated' || doc.template_id === null) {
      throw new ConflictException({ error: 'invalid_status' });
    }
    const row = await this.templates.findById(this.db, overrideTemplateId ?? doc.template_id);
    if (!row || row.doc_type !== doc.doc_type) {
      throw new NotFoundException({ error: 'template_not_found' });
    }
    // An override must be a currently active template; the document's own
    // template remains renderable even after it is superseded (regenerating
    // with unchanged inputs must stay reproducible).
    if (overrideTemplateId !== undefined && !row.active) {
      throw new NotFoundException({ error: 'template_not_found' });
    }
    return row;
  }

  private async requirementsFor(doc: DocumentRow): Promise<ExecutionRequirements> {
    if (doc.template_id === null) {
      return DEFAULT_REQUIREMENTS;
    }
    const row = await this.templates.findById(this.db, doc.template_id);
    if (!row) {
      return DEFAULT_REQUIREMENTS;
    }
    const parsed = ExecutionRequirementsSchema.safeParse(row.execution_requirements);
    return parsed.success ? parsed.data : DEFAULT_REQUIREMENTS;
  }

  private async requireLive(documentId: string): Promise<DocumentRow> {
    const doc = await this.documents.getLive(this.db, documentId);
    if (!doc) {
      throw new NotFoundException({ error: 'not_found' });
    }
    return doc;
  }

  private async lockLive(tx: Queryable, documentId: string): Promise<DocumentRow> {
    const doc = await this.documents.lockById(tx, documentId);
    if (!doc) {
      throw new NotFoundException({ error: 'not_found' });
    }
    return doc;
  }
}

function toDto(row: DocumentRow): DocumentDto {
  return {
    documentId: row.id,
    docType: row.doc_type,
    source: row.source,
    title: row.title,
    currentVersion: row.current_version,
    executionStatus: row.execution_status,
    executedAt: row.executed_at,
    legalHold: row.legal_hold,
    sealed: row.sealed,
    templateId: row.template_id,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

function toVersionDto(row: VersionRow): VersionDto {
  return {
    version: row.version,
    contentSha256: row.content_sha256.toString('hex'),
    sizeBytes: Number(row.size_bytes),
    mime: row.mime,
    createdBy: row.created_by,
    createdAt: row.created_at.toISOString(),
  };
}
