import { createHash, randomUUID } from 'node:crypto';
import {
  ConflictException,
  GoneException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
  UnprocessableEntityException,
} from '@nestjs/common';
import type { ExecutionStatus } from '@estate/contracts';
import { DekDestroyedError, type DekRepository } from '@estate/crypto';
import { SETTLEMENT_AUTHORITY, type SettlementEvidenceAuthority } from '@estate/settlement-client';
import { ContentCipher } from './content-cipher';
import { Db, type Queryable } from './db';
import { DocumentsAuthz, documentResource } from './authz.service';
import { DocumentsRepo, type DocumentRow } from './documents.repo';
import { EventsService } from './events.service';
import { allowedTransitions, allowsNewVersion, deEscalationTransitions } from './execution-status';
import {
  DEK_REPOSITORY,
  MALWARE_SCANNER,
  OBJECT_STORE,
  OCR_ENGINE,
  SYSTEM_ACTOR_ID,
} from './di-tokens';
import { sniffContent } from './content-sniff';
import type { MalwareScanner } from './malware-scanner';
import type { ObjectStore } from './object-store';
import type { OcrEngine } from './ocr';
import { htmlToText } from './search-index';
import { SearchIndexer } from './search-indexer';
import { SearchTokensRepo } from './search-tokens.repo';
import { RenderError, renderDocument } from './renderer';
import { TemplateEngine, TemplateIntegrityError } from './template-engine';
import { intakeSchemaFor, type ExecutionRequirements, type TemplateSource } from './template-model';
import { TemplatesRepo, type TemplateRow } from './templates.repo';
import { VersionsRepo, type VersionRow } from './versions.repo';
import {
  UPLOAD_MAX_BYTES,
  type GenerateDocumentInput,
  type NewVersionInput,
  type StatusTransitionInput,
  type UploadDocumentInput,
} from './schemas';

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

/**
 * One document, plus the execution transitions THIS document may take next.
 *
 * The ladder is parameterized by the template's `execution_requirements`
 * (docs/02 §4), which live in the sha256-verified template SOURCE — so only
 * this service can compute it. Returning it on the single-document read means a
 * client renders the attestations this instrument in this state actually
 * requires, instead of a hardcoded ladder that would silently offer a
 * will-with-no-witnesses path (docs/03 risk #8: the per-state
 * execution-requirement engine is a legal gate).
 *
 * Deliberately NOT on the list DTO: computing it costs a template load per
 * document, and a list is not where anyone attests anything.
 */
export interface DocumentDetailDto extends DocumentDto {
  allowedTransitions: ExecutionStatus[];
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
  /** utf8 for canonical-HTML (generated) content, base64 for binary uploads. */
  encoding: 'utf8' | 'base64';
  content: string;
}

export interface UploadResult {
  documentId: string;
  version: number;
  contentSha256: string;
  executionStatus: ExecutionStatus;
  ocrIndexed: boolean;
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

/** Object key for a version's encrypted derived OCR-text artifact. */
export function ocrObjectKey(documentId: string, version: number): string {
  return `documents/${documentId}/v${version}-ocr`;
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
    private readonly indexer: SearchIndexer,
    private readonly searchTokens: SearchTokensRepo,
    @Inject(DEK_REPOSITORY) private readonly deks: DekRepository,
    @Inject(OBJECT_STORE) private readonly store: ObjectStore,
    @Inject(MALWARE_SCANNER) private readonly scanner: MalwareScanner,
    @Inject(OCR_ENGINE) private readonly ocr: OcrEngine,
    // Only the evidence question — documents never asks about stages or vault.
    @Inject(SETTLEMENT_AUTHORITY) private readonly settlement: SettlementEvidenceAuthority,
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
    const title = input.title ?? source.title;
    // Generated documents are searchable through the same encrypted index as
    // uploads: tokens from the title + rendered text, HMAC'd per user.
    const tokens = this.indexer.forDocumentText(
      actor,
      `${title} ${htmlToText(rendered.bytes.toString('utf8'))}`,
    );
    await this.db.withTransaction(actor, async (tx) => {
      await this.documents.insert(tx, {
        id: documentId,
        userId: actor,
        docType: row.doc_type,
        templateId: row.id,
        source: 'generated',
        title,
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
      await this.searchTokens.replaceForDocument(tx, documentId, tokens);
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
    // The implicit concurrency expectation is the version we read; an
    // explicit If-Match must agree with it BEFORE any render/KMS work happens
    // (a stale writer gets its 409 first), and the locked re-check below
    // makes the expectation authoritative.
    const expectedVersion = ifMatch ?? doc.current_version;
    if (expectedVersion !== doc.current_version) {
      throw new ConflictException({ error: 'version_conflict' });
    }
    // Refuse to write a new version onto a document whose content DEK has been
    // crypto-shredded (legal erasure preserves the document row per docs/02, so
    // this path is reachable). Otherwise cipher.encrypt → getOrCreateDek would
    // mint a FRESH live DEK for a legally-erased document — defeating the shred
    // invariant — while documents.dek_id keeps pointing at the destroyed key,
    // leaving the new version un-servable. Surface Gone, exactly as reads do.
    const dek = await this.deks.findById(doc.dek_id);
    if (!dek || dek.destroyedAt !== null) {
      throw new GoneException({ error: 'content_erased' });
    }
    const row = await this.resolveRegenTemplate(doc, input.templateId);
    const source = await this.engine.load(row);
    const rendered = this.render(source, input.variables);
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
    // Re-index: the search index tracks the CURRENT version's content.
    const tokens = this.indexer.forDocumentText(
      doc.user_id,
      `${input.title ?? doc.title} ${htmlToText(rendered.bytes.toString('utf8'))}`,
    );
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
      await this.searchTokens.replaceForDocument(tx, documentId, tokens);
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

  /**
   * The upload ingest pipeline (docs/01 §2.6 Document Vault). The content is
   * UNTRUSTED INPUT (docs/03): strict base64 → size cap → magic-byte sniff
   * cross-checked against the declared mime → malware scan (FAIL CLOSED — a
   * scanner error rejects the upload, and an infected file is never stored
   * anywhere) → best-effort OCR (untrusted DATA: sealed into an encrypted
   * artifact + reduced to HMAC search tokens, never interpreted) → encrypt →
   * store → atomic metadata + version + index commit.
   */
  async upload(actor: string, input: UploadDocumentInput): Promise<UploadResult> {
    const content = Buffer.from(input.contentBase64, 'base64');
    if (content.length === 0 || content.length > UPLOAD_MAX_BYTES) {
      throw new UnprocessableEntityException({ error: 'unsupported_content' });
    }
    const sniffed = sniffContent(content, input.mime);
    if (!sniffed) {
      throw new UnprocessableEntityException({ error: 'unsupported_content' });
    }
    const documentId = randomUUID();
    this.authz.assertCan(actor, 'create', documentResource(documentId, actor));

    let scan;
    try {
      scan = await this.scanner.scan(content);
    } catch {
      // Fail closed: an unavailable scanner must never admit content.
      await this.events.scanRejected(actor, {
        kind: input.kind,
        format: sniffed.format,
        reason: 'scanner_error',
      });
      throw new ServiceUnavailableException({ error: 'scan_unavailable' });
    }
    // Fail closed: admit ONLY an explicit `clean` verdict. Anything else
    // (an `infected` result today; a future verdict variant such as
    // `suspicious`/`skipped` tomorrow) is rejected — content must never reach
    // storage on anything short of a positive all-clear. The union is
    // clean|infected, so this branch narrows to the infected variant; adding a
    // new variant surfaces here as a type error, forcing an explicit decision.
    if (scan.verdict !== 'clean') {
      await this.events.scanRejected(actor, {
        kind: input.kind,
        format: sniffed.format,
        reason: 'infected',
        signature: scan.signature,
      });
      throw new UnprocessableEntityException({ error: 'malware_detected' });
    }

    // Best-effort OCR — failure is non-fatal (scan is the gate, not this),
    // the document simply stores un-indexed beyond its title.
    let ocrText: string | null = null;
    try {
      const text = await this.ocr.extractText(content, sniffed.mime);
      ocrText = text.length > 0 ? text : null;
    } catch {
      ocrText = null;
    }

    const sha = createHash('sha256').update(content).digest();
    const shaHex = sha.toString('hex');
    const dekId = await this.cipher.getOrCreateDek(documentId);
    const { ciphertext } = await this.cipher.encrypt({
      documentId,
      ownerUserId: actor,
      version: 1,
      sha256Hex: shaHex,
      content,
    });
    const objectKey = contentObjectKey(documentId, 1, shaHex);
    await this.store.put(objectKey, ciphertext);
    if (ocrText !== null) {
      const artifact = await this.cipher.encryptOcr({
        documentId,
        ownerUserId: actor,
        version: 1,
        text: ocrText,
      });
      await this.store.put(ocrObjectKey(documentId, 1), artifact.ciphertext);
    }
    const tokens = this.indexer.forDocumentText(actor, `${input.title} ${ocrText ?? ''}`);
    await this.db.withTransaction(actor, async (tx) => {
      await this.documents.insert(tx, {
        id: documentId,
        userId: actor,
        docType: input.kind,
        templateId: null,
        source: 'uploaded',
        title: input.title,
        executionStatus: 'draft',
        dekId,
      });
      await this.versions.insert(tx, {
        documentId,
        version: 1,
        objectKey,
        contentSha256: sha,
        sizeBytes: content.length,
        mime: sniffed.mime,
        createdBy: actor,
        ocrIndexed: ocrText !== null,
      });
      await this.searchTokens.replaceForDocument(tx, documentId, tokens);
    });
    await this.events.documentUploaded(actor, documentId, {
      kind: input.kind,
      format: sniffed.format,
    });
    if (ocrText !== null) {
      await this.events.ocrIndexed(actor, documentId, { version: 1, tokens: tokens.length });
    }
    await this.events.versionCreated({
      actorId: actor,
      documentId,
      version: 1,
      docType: input.kind,
      source: 'uploaded',
    });
    return {
      documentId,
      version: 1,
      contentSha256: shaHex,
      executionStatus: 'draft',
      ocrIndexed: ocrText !== null,
    };
  }

  /** Attest an execution-status transition (state-machine validated). */
  async transitionStatus(
    actor: string,
    documentId: string,
    input: StatusTransitionInput,
  ): Promise<DocumentDetailDto> {
    if ((input.status === 'executed') !== (input.executedAt !== undefined)) {
      // executedAt accompanies exactly the `executed` attestation.
      throw new UnprocessableEntityException({ error: 'invalid_transition' });
    }
    const updated = await this.db.withTransaction(actor, async (tx) => {
      const locked = await this.lockLive(tx, documentId);
      this.authz.assertCan(actor, 'update', documentResource(documentId, locked.user_id));
      // The WRITE narrows the same way the read does, and for the same reason:
      // an unverifiable template must not trap an owner in an attested status
      // with no way back. It permits DE-ESCALATION only — never a rung that
      // would advance the ladder on formalities nobody can verify.
      const requirements = await this.resolveRequirements(locked);
      const permitted =
        requirements === null
          ? deEscalationTransitions(locked.execution_status)
          : allowedTransitions(locked.execution_status, requirements);
      if (!permitted.includes(input.status)) {
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
    // The NEXT rung comes back with the answer: after an attestation the
    // remaining formalities have changed, and a client that had to re-read to
    // learn that would render a stale ladder for one round trip.
    const fresh = await this.requireLive(documentId);
    return { ...toDto(fresh), allowedTransitions: await this.allowedTransitionsFor(fresh) };
  }

  /**
   * Soft delete (docs/02: no hard deletes). Step-up gated at the controller —
   * deletion requests are a mandatory step-up action (docs/01 §5). Legal hold
   * wins over the owner: a held document cannot be deleted by anyone through
   * the API.
   *
   * THIS SAID "the retention job owns crypto-shredding" AND THERE IS NO
   * RETENTION JOB — the third comment in the repo to describe one, after
   * docs/02 §conventions and `packages/crypto/src/dek.ts` (both corrected in
   * M25 PR0, which counted two and was itself one short). Crypto-shredding is
   * owned by the M25 erasure path, which is owner-initiated and runs under the
   * app role; `destroyDek` still has no production caller until M25 PR3.
   * Soft delete does not shred anything and never did.
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

  async get(actor: string, documentId: string): Promise<DocumentDetailDto> {
    const doc = await this.requireLive(documentId);
    this.authz.assertCan(actor, 'read', documentResource(documentId, doc.user_id));
    return { ...toDto(doc), allowedTransitions: await this.allowedTransitionsFor(doc) };
  }

  /**
   * The transitions this document may take next — FAIL CLOSED, where closed
   * means REFUSING TO ASSERT A FORMALITY WE CANNOT VERIFY rather than refusing
   * every transition.
   *
   * `requirementsFor` will not guess when the ladder cannot be read from a
   * sha256-verified template source (a soft-deleted template row, a body
   * integrity mismatch), and that refusal must not be softened: offering
   * `witnessed` for a will whose witness requirement is unknown is the
   * fail-open the M4 review closed. But withdrawing EVERYTHING was its own
   * defect (M12 review): `revoked` and `superseded` never depended on the
   * formalities, so an unverifiable template was stripping the owner's only
   * de-escalation, permanently — inverting the M6 rule that the protective
   * action must never be harder than the permissive one. What survives is
   * `deEscalationTransitions` — revoke and supersede, a strict subset of the
   * real ladder under every profile. Advancing is still withheld.
   *
   * This is a READ, so it degrades rather than erroring: failing the whole
   * document read would make an otherwise-intact document unopenable because
   * of its template's state.
   */
  private async allowedTransitionsFor(doc: DocumentRow): Promise<ExecutionStatus[]> {
    const requirements = await this.resolveRequirements(doc);
    return requirements === null
      ? deEscalationTransitions(doc.execution_status)
      : allowedTransitions(doc.execution_status, requirements);
  }

  /**
   * The document's formalities, or null when they cannot be verified.
   *
   * A TEMPLATE INTEGRITY FAILURE IS AUDITED HERE, because here is where it is
   * caught. `body_sha256` exists to detect a substituted or corrupted template
   * body (docs/03 TB4), and both callers of this method degrade rather than
   * erroring — so without this emit, the one signal that pin exists to produce
   * would end in a bare `catch` and leave no trace in the audit chain, no log,
   * and a 200 on the wire. Absence of a template row is NOT audited as tamper:
   * it is an ordinary consequence of a soft-deleted template.
   */
  private async resolveRequirements(doc: DocumentRow): Promise<ExecutionRequirements | null> {
    try {
      return await this.requirementsFor(doc);
    } catch (err) {
      if (err instanceof TemplateIntegrityError) {
        await this.events.templateIntegrityFailed(doc.user_id, doc.id, doc.template_id);
      }
      return null;
    }
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
    // Canonical HTML travels as utf8; binary uploads as base64.
    const encoding = versionRow.mime === 'text/html' ? 'utf8' : 'base64';
    return {
      documentId,
      version: versionRow.version,
      mime: versionRow.mime,
      contentSha256: shaHex,
      encoding,
      content: content.toString(encoding),
    };
  }

  /**
   * M7 evidence read: a settlement OPERATOR (never the owner) reads a version
   * registered as death-certificate evidence on a live case. Authorization is
   * settlement's, not Cedar's: the caller's own bearer is forwarded and
   * settlement answers only if the caller is an allowlisted operator on a case
   * listing exactly this (documentId, version) as evidence. Fail closed — an
   * unreachable settlement, a refusal, and an unknown document are all the
   * same uniform 404 (no evidence-registration oracle).
   *
   * The owner cross-check is load-bearing: settlement records which user
   * ATTACHED the evidence, and this service refuses when the document's real
   * owner differs — otherwise a reporter could register someone else's
   * document id as "evidence" and have an operator decrypt it for them.
   */
  async getEvidenceContent(
    actor: string,
    bearerToken: string,
    documentId: string,
    version: number,
  ): Promise<ContentDto> {
    const authority = await this.settlement.checkEvidenceRead({ bearerToken, documentId, version });
    if (!authority.allowed) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const doc = await this.documents.getLive(this.db, documentId);
    if (!doc || doc.user_id !== authority.ownerUserId) {
      throw new NotFoundException({ error: 'not_found' });
    }
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
        // By construction the caller is a settlement operator — checkEvidenceRead
        // only answers for allowlisted operators — so the decrypt audits as one.
        // Without this the wrapper's 'user' default misclassifies the one
        // operator-driven decrypt in the product (docs/03 §4 TB4 keys its
        // per-principal baseline on actor class).
        actorType: 'operator',
        purpose: 'evidence_content_read',
      });
    } catch (err) {
      if (err instanceof DekDestroyedError) {
        throw new GoneException({ error: 'content_erased' });
      }
      throw err;
    }
    await this.events.evidenceAccessed(actor, documentId, doc.user_id, {
      version: versionRow.version,
      caseId: authority.caseId,
    });
    const encoding = versionRow.mime === 'text/html' ? 'utf8' : 'base64';
    return {
      documentId,
      version: versionRow.version,
      mime: versionRow.mime,
      contentSha256: shaHex,
      encoding,
      content: content.toString(encoding),
    };
  }

  /**
   * Apply or lift a legal hold across an estate's documents (M7 PR2). This
   * closes the M4 gap where `legal_hold` was ENFORCED (softDelete refuses a
   * held document) but had no writer — the setting surface was explicitly
   * assigned to settlement.
   *
   * Called only through the internal, service-credential-guarded route: it is
   * not a user capability, and no bearer token can reach it. Idempotent, and
   * the audit records how many documents actually moved.
   *
   * The transaction actor is SYSTEM_ACTOR_ID, not the owner: `app.actor_id`
   * feeds the `documents_versions` trigger, and this is a platform action the
   * owner did not and could not take. Attributing it to them would make the
   * append-only version history of a frozen estate read as though the
   * decedent froze their own documents the day a stranger reported them dead
   * — and the audit event for the same operation already records it correctly
   * as a service action, so the two would disagree. (M9 security review; the
   * route had no caller before M9 PR2, so no such row had ever been written.)
   */
  async setEstateLegalHold(
    ownerUserId: string,
    hold: boolean,
    caseId: string,
  ): Promise<{ changed: number }> {
    const changed = await this.db.withTransaction(SYSTEM_ACTOR_ID, (tx) =>
      this.documents.setLegalHoldForOwner(tx, ownerUserId, hold),
    );
    await this.events.legalHoldSet(ownerUserId, { hold, changed, caseId });
    return { changed };
  }

  /**
   * Encrypted search: reduce the query through the SAME tokenizer + per-user
   * HMAC as indexing and match ciphertext-side (AND semantics). Nothing is
   * decrypted to serve a search, so there is no decrypt audit event; results
   * are the caller's own documents by construction (per-user key + user_id
   * join) with a defensive per-item authz filter on top.
   */
  async search(actor: string, query: string): Promise<DocumentDto[]> {
    const tokens = this.indexer.forQuery(actor, query);
    if (tokens.length === 0) {
      return [];
    }
    const documentIds = await this.searchTokens.findMatchingAll(this.db, actor, tokens);
    const results: DocumentDto[] = [];
    for (const documentId of documentIds) {
      const row = await this.documents.getLive(this.db, documentId);
      if (row && this.authz.can(actor, 'read', documentResource(row.id, row.user_id))) {
        results.push(toDto(row));
      }
    }
    return results;
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
    // Uploads carry no template and no state-mandated execution ladder.
    if (doc.template_id === null) {
      return DEFAULT_REQUIREMENTS;
    }
    // A GENERATED instrument's execution ladder MUST come from its template and
    // MUST fail closed: a missing template (e.g. soft-deleted, so findById
    // returns null) or a tampered/unparseable requirements value must NEVER
    // silently drop a will/POA to the weakest (no-witness, no-notary) ladder
    // (docs/03 risk #8 — the per-state execution-requirement engine is a legal
    // gate). Read the requirements from the sha256-verified template SOURCE via
    // engine.load, so the body_sha256 integrity pin that protects the rendered
    // instrument also protects the formalities gate — closing the asymmetry
    // where execution_requirements was read from an unverified DB column.
    const row = await this.templates.findById(this.db, doc.template_id);
    if (!row) {
      throw new ConflictException({ error: 'template_unavailable' });
    }
    const source = await this.engine.load(row);
    return source.executionRequirements;
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
