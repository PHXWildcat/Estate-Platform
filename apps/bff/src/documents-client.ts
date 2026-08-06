import { z } from 'zod';
import { bffError } from './identity-client';

/**
 * Client for the document service (apps/services/documents) — the BFF's THIRD
 * non-identity downstream, on exactly the assets/assistant terms: THE BFF
 * FORWARDS THE CALLER'S OWN BEARER TOKEN, injects no identity header, and holds
 * no credential for documents. The service's owner-only Cedar PEP therefore
 * decides every request against the session the browser already had, and a
 * compromised BFF replays the sessions it is currently serving rather than
 * minting new ones.
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT DO. It never reaches the two internal,
 * service-credential-guarded routes (`PUT /internal/v1/legal-hold`, the M7
 * evidence read). Those are not user capabilities and no bearer token can open
 * them; a client that named them would be aspirational authority in a file that
 * holds no credential to exercise it.
 *
 * Same error contract as the other clients: downstream response text is NEVER
 * forwarded to GraphQL clients. Recognized machine tokens become stable codes;
 * everything else is a masked generic error.
 */

/**
 * One template-variable declaration, re-validated on the way through.
 *
 * The service already re-validates this column on its way out (a corrupted
 * value cannot leak arbitrary JSON into an API response), and this parse is the
 * second half of the same rule applied at the edge: the web app builds an
 * intake FORM from these declarations, so a shape it does not understand must
 * fail here rather than render a control that silently drops a variable a legal
 * instrument depends on.
 */
export const TemplateVariableSchema = z.discriminatedUnion('kind', [
  z.object({
    name: z.string().min(1),
    kind: z.literal('text'),
    label: z.string().min(1).optional(),
    required: z.boolean(),
    maxLength: z.number().int().positive(),
  }),
  z.object({
    name: z.string().min(1),
    kind: z.literal('boolean'),
    label: z.string().min(1).optional(),
    required: z.boolean(),
  }),
  z.object({
    name: z.string().min(1),
    kind: z.literal('date'),
    label: z.string().min(1).optional(),
    required: z.boolean(),
  }),
  z.object({
    name: z.string().min(1),
    kind: z.literal('enum'),
    label: z.string().min(1).optional(),
    required: z.boolean(),
    options: z.array(z.string().min(1)).min(2),
  }),
]);
export type TemplateVariable = z.infer<typeof TemplateVariableSchema>;

/** Per-state formalities (docs/02 §4 `execution_requirements`). */
export const ExecutionRequirementsSchema = z.object({
  witnesses: z.number().int().min(0),
  notarization: z.boolean(),
  selfProvingAffidavit: z.boolean(),
});
export type ExecutionRequirements = z.infer<typeof ExecutionRequirementsSchema>;

export const DocumentTemplateSchema = z.object({
  templateId: z.string().min(1),
  docType: z.string().min(1),
  state: z.string().min(1),
  version: z.number().int(),
  legalReviewAt: z.string().min(1),
  executionRequirements: ExecutionRequirementsSchema,
  variables: z.array(TemplateVariableSchema),
});
export type DocumentTemplate = z.infer<typeof DocumentTemplateSchema>;

/**
 * Document METADATA. `title` is the one plaintext, user-authored label column
 * in the documents cluster (the M4 decision, on the `assets_view.title`
 * precedent) — everything with real content in it lives inside the encrypted
 * blob and arrives only through `content()`, one explicit read at a time.
 */
export const DocumentSchema = z.object({
  documentId: z.string().min(1),
  docType: z.string().min(1),
  source: z.string().min(1),
  title: z.string(),
  currentVersion: z.number().int(),
  executionStatus: z.string().min(1),
  executedAt: z.string().nullable(),
  legalHold: z.boolean(),
  sealed: z.boolean(),
  templateId: z.string().nullable(),
  createdAt: z.string().min(1),
  updatedAt: z.string().min(1),
});
export type Document = z.infer<typeof DocumentSchema>;

export const DocumentVersionSchema = z.object({
  version: z.number().int(),
  contentSha256: z.string().min(1),
  sizeBytes: z.number().int(),
  mime: z.string().min(1),
  createdAt: z.string().min(1),
});
export type DocumentVersion = z.infer<typeof DocumentVersionSchema>;

/**
 * ONE VERSION'S DECRYPTED CONTENT, and the only response on this client that
 * carries any. Fetching it is an AUDITED DECRYPT downstream
 * (`crypto.field.decrypted` plus the product-level `document.content.viewed`),
 * which is why nothing here batches, prefetches or caches it: one deliberate
 * user action is meant to produce exactly one such event.
 *
 * `encoding` is 'utf8' for canonical HTML (generated instruments) and 'base64'
 * for binary uploads. The web app renders the HTML case inside a sandboxed
 * iframe and never as app-origin markup.
 */
export const DocumentContentSchema = z.object({
  documentId: z.string().min(1),
  version: z.number().int(),
  mime: z.string().min(1),
  contentSha256: z.string().min(1),
  encoding: z.enum(['utf8', 'base64']),
  content: z.string(),
});
export type DocumentContent = z.infer<typeof DocumentContentSchema>;

export const GenerateResultSchema = z.object({
  documentId: z.string().min(1),
  version: z.number().int(),
  contentSha256: z.string().min(1),
  executionStatus: z.string().min(1),
});
export type GenerateResult = z.infer<typeof GenerateResultSchema>;

/** An intake value: the service accepts strings and booleans, nothing else. */
export type IntakeValue = string | boolean;

export interface GenerateInput {
  readonly docType: string;
  readonly state: string;
  readonly templateId?: string;
  readonly title?: string;
  readonly variables: Readonly<Record<string, IntakeValue>>;
}

export interface RegenerateInput {
  readonly templateId?: string;
  readonly title?: string;
  readonly variables: Readonly<Record<string, IntakeValue>>;
}

export interface DocumentsClient {
  templates(accessToken: string, state: string): Promise<DocumentTemplate[]>;
  list(accessToken: string): Promise<Document[]>;
  get(accessToken: string, documentId: string): Promise<Document>;
  versions(accessToken: string, documentId: string): Promise<DocumentVersion[]>;
  content(accessToken: string, documentId: string, version: number): Promise<DocumentContent>;
  generate(accessToken: string, input: GenerateInput): Promise<GenerateResult>;
  regenerate(
    accessToken: string,
    documentId: string,
    input: RegenerateInput,
  ): Promise<GenerateResult>;
}

type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

export class FetchDocumentsClient implements DocumentsClient {
  private readonly fetchFn: FetchFn;

  constructor(
    private readonly baseUrl: string,
    fetchFn?: FetchFn,
  ) {
    this.fetchFn = fetchFn ?? ((input, init): Promise<Response> => globalThis.fetch(input, init));
  }

  /**
   * The template catalog for one state. Template metadata is PRODUCT CONTENT,
   * not user data — the service says so explicitly — so this carries nothing
   * about the caller beyond the fact that they asked.
   */
  async templates(accessToken: string, state: string): Promise<DocumentTemplate[]> {
    const res = await this.request(
      'GET',
      `/v1/templates?state=${encodeURIComponent(state)}`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parse(res, z.array(DocumentTemplateSchema));
  }

  async list(accessToken: string): Promise<Document[]> {
    const res = await this.request('GET', '/v1/documents', accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parse(res, z.array(DocumentSchema));
  }

  async get(accessToken: string, documentId: string): Promise<Document> {
    const res = await this.request(
      'GET',
      `/v1/documents/${encodeURIComponent(documentId)}`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parse(res, DocumentSchema);
  }

  async versions(accessToken: string, documentId: string): Promise<DocumentVersion[]> {
    const res = await this.request(
      'GET',
      `/v1/documents/${encodeURIComponent(documentId)}/versions`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parse(res, z.array(DocumentVersionSchema));
  }

  /** One audited decrypt. See DocumentContentSchema. */
  async content(
    accessToken: string,
    documentId: string,
    version: number,
  ): Promise<DocumentContent> {
    const res = await this.request(
      'GET',
      `/v1/documents/${encodeURIComponent(documentId)}/versions/${encodeURIComponent(
        String(version),
      )}/content`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parse(res, DocumentContentSchema);
  }

  /** Step-up gated downstream (docs/01 §5): a 403 becomes STEPUP_REQUIRED. */
  async generate(accessToken: string, input: GenerateInput): Promise<GenerateResult> {
    const res = await this.request('POST', '/v1/documents/generate', accessToken, {
      body: {
        docType: input.docType,
        state: input.state,
        ...(input.templateId !== undefined ? { templateId: input.templateId } : {}),
        ...(input.title !== undefined ? { title: input.title } : {}),
        variables: input.variables,
      },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parse(res, GenerateResultSchema);
  }

  /**
   * Regeneration as the next version — equally step-up gated, and refused
   * downstream once signing has started, because a signed instrument's content
   * is a legal record.
   */
  async regenerate(
    accessToken: string,
    documentId: string,
    input: RegenerateInput,
  ): Promise<GenerateResult> {
    const res = await this.request(
      'POST',
      `/v1/documents/${encodeURIComponent(documentId)}/versions`,
      accessToken,
      {
        body: {
          ...(input.templateId !== undefined ? { templateId: input.templateId } : {}),
          ...(input.title !== undefined ? { title: input.title } : {}),
          variables: input.variables,
        },
      },
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parse(res, GenerateResultSchema);
  }

  private async request(
    method: 'GET' | 'POST',
    path: string,
    accessToken: string,
    options: { body?: Record<string, unknown> } = {},
  ): Promise<Response> {
    const headers: Record<string, string> = { authorization: `Bearer ${accessToken}` };
    const init: RequestInit = { method, headers };
    if (options.body !== undefined) {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(options.body);
    }
    try {
      return await this.fetchFn(`${this.baseUrl}${path}`, init);
    } catch {
      // Network/DNS failure. Plain Error ⇒ masked by yoga; cause never exposed.
      throw new Error('documents service unreachable');
    }
  }

  private async parse<T extends z.ZodTypeAny>(res: Response, schema: T): Promise<z.infer<T>> {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new Error('documents response was not JSON');
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      // Contract drift ⇒ no data, never a guess. Field paths only, never values.
      throw new Error('documents response failed validation');
    }
    return parsed.data as z.infer<T>;
  }

  /**
   * Downstream status + machine token → a stable code. The mappings that carry
   * a decision rather than a translation:
   *
   * - `template_not_found` is kept APART from a missing document. Both are 404s
   *   and they mean opposite things to a person: "we have no reviewed template
   *   for that instrument in that state" is a fact about the catalog, while
   *   "that document is not available" is a fact about their own account.
   * - `content_erased` (410) gets its own code because the answer is permanent.
   *   Rendering a crypto-shredded version as a transient failure would invite
   *   someone to retry forever for a key that was destroyed on purpose.
   * - `invalid_status` and `version_conflict` (both 409) are separated for the
   *   same reason: one means "revoke or supersede first", the other means
   *   "someone else moved this on, reload" — and a single "conflict" would leave
   *   the user guessing which.
   * - A NON-STEP-UP 403 becomes NOT_FOUND at this edge. The service answers 404
   *   for a document that does not exist and 403 for one that exists and is
   *   somebody else's, which is the 404-vs-403 oracle its own M4 review recorded
   *   as an open follow-up. Collapsing them HERE narrows it for browser traffic;
   *   it does not close the service-level finding, which stands for any other
   *   caller and is where the real fix belongs.
   */
  private async mapError(res: Response): Promise<Error> {
    const token = errorToken(await this.readJson(res));
    if (res.status === 401) {
      return bffError('UNAUTHENTICATED');
    }
    if (res.status === 403 && token === 'stepup_required') {
      return bffError('STEPUP_REQUIRED');
    }
    if (res.status === 403) {
      return bffError('NOT_FOUND');
    }
    if (res.status === 404) {
      return bffError(token === 'template_not_found' ? 'TEMPLATE_NOT_FOUND' : 'NOT_FOUND');
    }
    if (res.status === 410) {
      return bffError('CONTENT_ERASED');
    }
    if (res.status === 409 && token === 'version_conflict') {
      return bffError('VERSION_CONFLICT');
    }
    if (res.status === 409 && token === 'invalid_status') {
      return bffError('DOCUMENT_NOT_EDITABLE');
    }
    if (res.status === 400 || res.status === 422) {
      return bffError('INVALID_REQUEST');
    }
    return new Error(`documents responded with status ${res.status}`);
  }

  private async readJson(res: Response): Promise<unknown> {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }
}

/** The peer's machine token, or null. Never its message. */
function errorToken(body: unknown): string | null {
  const parsed = z.object({ error: z.string().min(1) }).safeParse(body);
  return parsed.success ? parsed.data.error : null;
}
