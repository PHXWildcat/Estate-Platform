import type { IncomingMessage, ServerResponse } from 'node:http';
import type { GraphQLSchema } from 'graphql';
import { createSchema } from 'graphql-yoga';
import type { MfaLevel } from '@estate/contracts';
import type { Asset, AssetsClient, CreateResult, NetWorth } from './assets-client';
import type {
  AnalysisName,
  AnalysisView,
  AssistantClient,
  Conversation,
  Transcript,
  Turn,
} from './assistant-client';
import type {
  Document,
  DocumentContent,
  DocumentTemplate,
  DocumentVersion,
  DocumentsClient,
  GenerateResult,
  IntakeValue,
} from './documents-client';
import {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  clearSessionCookies,
  parseCookies,
  setSessionCookies,
} from './cookies';
import { bffError, type IdentityClient } from './identity-client';

/**
 * Auth slice of the BFF schema (Milestone 1). Deliberately small: login and
 * refresh return ONLY `{ ok }` — tokens live exclusively in httpOnly cookies
 * (see cookies.ts). `sessionId` is intentionally not exposed to the client.
 */
export const typeDefs = /* GraphQL */ `
  enum MfaLevel {
    NONE
    MFA
    STEPUP
  }

  type Session {
    userId: ID!
    mfaLevel: MfaLevel!
    "True while the session's step-up window (fresh ≤5 min) is open."
    stepUpFresh: Boolean!
  }

  type Ok {
    ok: Boolean!
  }

  type TotpEnroll {
    otpauthUri: String!
  }

  type Asset {
    assetId: ID!
    category: String!
    title: String!
    "Decimal string — money is never a Float."
    estValue: String
    valuationAsOf: String
    ownershipPct: Float!
    inTrust: Boolean!
    version: String!
  }

  type NetWorth {
    "Decimal string: Σ estValue × ownership%, over assets with a known value."
    totalValue: String!
    assetCount: Int!
    valuedAssetCount: Int!
    inTrustValue: String!
  }

  type CreatedAsset {
    assetId: ID!
    version: String!
  }

  """
  Why an analysis has a STATUS rather than throwing. The readiness page asks
  for all four at once, so one unavailable analysis must not blank the other
  three. Four values where the service has three: DISABLED is the master
  consent switch being off, which is the one the user can act on.
  """
  enum AnalysisStatus {
    OK
    UNAVAILABLE
    REFUSED
    DISABLED
  }

  type FindingSubject {
    "asset | document | estate."
    kind: String!
    "The owning service's row id, or null for an estate-level finding."
    ref: ID
    "User-authored title, or null. Rendered as data, never as instructions."
    label: String
  }

  """
  One deterministic finding. 'code' is a closed token the UI turns into a
  sentence — the analyser computes, and no model is involved on this path.
  """
  type Finding {
    code: String!
    "high | medium | info."
    severity: String!
    subject: FindingSubject!
    "Numbers behind the code: counts, enum tokens, money as decimal STRINGS."
    detail: JSON!
  }

  type Analysis {
    status: AnalysisStatus!
    "Enum token when the analysis did not run ('reference_unreviewed'); never prose."
    reason: String
    "Empty for every status but OK — a failure is never an empty result."
    findings: [Finding!]!
    "docs/01 §2.8's non-legal-advice watermark. Present on every status."
    disclaimer: String!
  }

  type Readiness {
    funding: Analysis!
    missingDocuments: Analysis!
    beneficiaryConflicts: Analysis!
    estateTax: Analysis!
  }

  "Opaque JSON for a finding's detail map (scalars only, validated upstream)."
  scalar JSON

  type Conversation {
    conversationId: ID!
    createdAt: String!
    updatedAt: String!
  }

  """
  One message. 'text' is MODEL-AUTHORED on the assistant side and is UNTRUSTED
  MARKUP: the web app renders it through MessageText, which builds text nodes
  and nothing else, so a model-emitted image or link is characters on a screen
  rather than a request (docs/03 §6d).
  """
  type TranscriptMessage {
    messageId: ID!
    seq: Int!
    "user | assistant."
    role: String!
    text: String!
    createdAt: String!
  }

  type Transcript {
    conversationId: ID!
    messages: [TranscriptMessage!]!
  }

  type Turn {
    conversationId: ID!
    messageId: ID!
    text: String!
    "How many read-only retrievals the assistant made while composing this."
    toolCalls: Int!
  }

  """
  One declared intake variable of a template. The web app builds its
  questionnaire from these — the template is the authority on what a
  state-specific instrument asks for, never the client.
  """
  type TemplateVariable {
    name: String!
    "text | boolean | date | enum."
    kind: String!
    label: String
    required: Boolean!
    "Text variables only: the template's own cap on the value's length."
    maxLength: Int
    "Enum variables only."
    options: [String!]
  }

  "Per-state formalities (docs/02 §4). The execution ladder is built from these."
  type ExecutionRequirements {
    witnesses: Int!
    notarization: Boolean!
    selfProvingAffidavit: Boolean!
  }

  """
  A published, attorney-signed-off template. PRODUCT CONTENT, not user data:
  the service serves the catalog to any authenticated caller and there is no
  mutation surface anywhere — templates publish from in-repo sources by CLI, so
  git review IS the sign-off gate.
  """
  type DocumentTemplate {
    templateId: ID!
    docType: String!
    state: String!
    version: Int!
    legalReviewAt: String!
    executionRequirements: ExecutionRequirements!
    variables: [TemplateVariable!]!
  }

  """
  Document METADATA. 'title' is the one plaintext user-authored label in the
  documents cluster (accepted low-sensitivity metadata, the assets_view.title
  precedent); everything else with content in it lives inside the encrypted
  blob and arrives only through documentContent, one deliberate read at a time.
  """
  type Document {
    documentId: ID!
    docType: String!
    "generated | uploaded."
    source: String!
    title: String!
    currentVersion: Int!
    executionStatus: String!
    "ISO date, present only once 'executed' has been attested."
    executedAt: String
    "Set by settlement when an estate is frozen. Blocks deletion."
    legalHold: Boolean!
    "The owner moved it to Zone A — the server can no longer read it."
    sealed: Boolean!
    templateId: ID
    createdAt: String!
    updatedAt: String!
  }

  type DocumentVersion {
    version: Int!
    contentSha256: String!
    sizeBytes: Int!
    mime: String!
    createdAt: String!
  }

  """
  One version's decrypted content. FETCHING THIS IS AN AUDITED DECRYPT
  downstream, so it is never batched into a list query and never prefetched:
  one user action is meant to produce exactly one such event.

  'encoding' is utf8 for canonical HTML (generated instruments) and base64 for
  binary uploads. The HTML case is rendered inside a sandboxed iframe and never
  as app-origin markup — document content is untrusted input (docs/03 risk #6).
  """
  type DocumentContent {
    documentId: ID!
    version: Int!
    mime: String!
    contentSha256: String!
    "utf8 | base64."
    encoding: String!
    content: String!
  }

  type GeneratedDocument {
    documentId: ID!
    version: Int!
    contentSha256: String!
    executionStatus: String!
  }

  """
  One intake answer. Exactly one of 'text' and 'boolean' must be supplied — a
  variable with neither, or both, is refused before anything downstream sees it.

  This is a TYPED input rather than the JSON scalar the readiness surface uses
  for finding detail. That scalar is an OUTPUT of data the service already
  validated; putting an untyped shape on the one mutation that reaches a legal
  instrument's renderer would be the opposite trade.
  """
  input DocumentVariableInput {
    name: String!
    text: String
    boolean: Boolean
  }

  type Query {
    "Current session, or null when unauthenticated."
    session: Session
    "The caller's assets. The BFF forwards the caller's own bearer token."
    assets: [Asset!]!
    netWorth: NetWorth!
    """
    The four deterministic analyses, computed by the assistant service from the
    caller's own estate. No model provider is involved on this path: the
    analysers compute, and consent scopes gate egress rather than this read.
    """
    readiness: Readiness!
    "Consent scopes the caller has granted the assistant. Absence is denial."
    consents: [String!]!
    "The caller's own conversations."
    conversations: [Conversation!]!
    """
    One decrypted transcript. A conversation that does not exist and one
    belonging to somebody else answer identically — the service's uniform
    not-found, kept uniform here so an id cannot be probed.
    """
    conversation(conversationId: ID!): Transcript!
    "The published templates for one state. Product content, not user data."
    documentTemplates(state: String!): [DocumentTemplate!]!
    "The caller's own documents — metadata only, no content is decrypted."
    documents: [Document!]!
    document(documentId: ID!): Document!
    documentVersions(documentId: ID!): [DocumentVersion!]!
    """
    One version's content. Each call is an audited decrypt downstream, so ask
    for it only when someone has asked to read that exact version.
    """
    documentContent(documentId: ID!, version: Int!): DocumentContent!
  }

  type Mutation {
    register(email: String!, password: String!): Ok!
    "Sets httpOnly session cookies; no token material in the response body."
    login(email: String!, password: String!): Ok!
    "Rotates the token pair using the refresh cookie; re-sets both cookies."
    refresh: Ok!
    "Revokes THIS session server-side, then expires both cookies."
    logout: Ok!
    totpEnroll: TotpEnroll!
    totpVerify(code: String!): Ok!
    stepUp(code: String!): Ok!
    "Step-up-gated demo action (stands in for data export)."
    exportDemo: Ok!
    """
    Records an asset. A valuation is all-or-nothing: supply estValue,
    valuationAsOf and valuationSource together, or none of them — an amount
    with no date and no provenance is not an auditable claim.
    """
    createAsset(
      category: String!
      title: String!
      estValue: String
      valuationAsOf: String
      valuationSource: String
    ): CreatedAsset!
    """
    Grants one assistant consent scope. STEP-UP GATED downstream (docs/01 §5:
    a grant widens what may reach a third-party model provider, which is
    export-class), so this can fail with STEPUP_REQUIRED. Returns the caller's
    full grant set so a client never has to guess the result.
    """
    grantConsent(scope: String!): [String!]!
    """
    Revokes one scope. Deliberately NOT step-up gated, the M6
    emergency-access-denial rule: the protective action must never be harder
    than the permissive one.
    """
    revokeConsent(scope: String!): [String!]!
    startConversation: Conversation!
    """
    Take one turn. Slow by nature — it waits on a real provider round trip —
    and refused outright when the assistant.enabled master switch is off, so a
    client should ask for consents before offering a composer.
    """
    sendMessage(conversationId: ID!, text: String!): Turn!
    "Soft delete downstream: the ciphertext survives, erasure is a separate act."
    deleteConversation(conversationId: ID!): Ok!
    """
    Generates a state-specific instrument from a reviewed template. STEP-UP
    GATED downstream (docs/01 §5 names document generation explicitly), so this
    can fail with STEPUP_REQUIRED — the client is expected to collect a code and
    retry the same call.
    """
    generateDocument(
      docType: String!
      state: String!
      templateId: ID
      title: String
      variables: [DocumentVariableInput!]!
    ): GeneratedDocument!
    """
    Re-renders a document as its next version. Equally step-up gated, and
    refused with DOCUMENT_NOT_EDITABLE once signing has started: a signed
    instrument's content is a legal record, so the way forward is to revoke or
    supersede it rather than rewrite it under the signatures.
    """
    regenerateDocument(
      documentId: ID!
      templateId: ID
      title: String
      variables: [DocumentVariableInput!]!
    ): GeneratedDocument!
  }
`;

/** Server context wired by the express↔yoga integration in app.ts. */
export interface RequestContext {
  req: IncomingMessage;
  res: ServerResponse;
}

export interface SchemaDeps {
  identity: IdentityClient;
  assets: AssetsClient;
  assistant: AssistantClient;
  documents: DocumentsClient;
  /** Adds the Secure attribute to session cookies (production). */
  secureCookies: boolean;
  /** Clock override for tests. */
  now?: () => number;
}

interface SessionPayload {
  readonly userId: string;
  readonly mfaLevel: 'NONE' | 'MFA' | 'STEPUP';
  readonly stepUpFresh: boolean;
}

interface CredentialsArgs {
  readonly email: string;
  readonly password: string;
}

interface CodeArgs {
  readonly code: string;
}

interface ScopeArgs {
  readonly scope: string;
}

interface ConversationArgs {
  readonly conversationId: string;
}

interface DocumentArgs {
  readonly documentId: string;
}

interface DocumentVariableInput {
  readonly name: string;
  readonly text?: string | null;
  readonly boolean?: boolean | null;
}

/**
 * Collapse the typed intake list into the record the document service takes.
 *
 * EXACTLY ONE VALUE PER VARIABLE, AND NO DUPLICATE NAMES. Both refusals happen
 * here rather than downstream, and neither is decoration:
 *
 * - A variable carrying neither value, or both, is ambiguous, and the one thing
 *   that must never happen to a will is a silently-chosen answer. The renderer
 *   already fails closed on an unsubstitutable placeholder, but "fails closed
 *   two layers away" is a worse error message than "that answer was malformed".
 * - A duplicate name would resolve by last-write-wins in the record, so the
 *   value the user saw in the form and the value rendered into the instrument
 *   could differ with nothing in between to notice.
 *
 * Names and values are NOT inspected beyond that: what a variable may contain
 * is the TEMPLATE's declaration to enforce, and the service re-validates the
 * whole payload against the resolved template's typed intake schema before a
 * render can happen. Guessing at that here would be a second, drifting copy of
 * a legal gate.
 */
function intakeRecord(inputs: readonly DocumentVariableInput[]): Record<string, IntakeValue> {
  const record: Record<string, IntakeValue> = {};
  for (const input of inputs) {
    const { text, boolean } = input;
    const hasText = typeof text === 'string';
    const hasBoolean = typeof boolean === 'boolean';
    if (hasText === hasBoolean) {
      throw bffError('INVALID_REQUEST');
    }
    if (Object.prototype.hasOwnProperty.call(record, input.name)) {
      throw bffError('INVALID_REQUEST');
    }
    record[input.name] = hasText ? text : (boolean as boolean);
  }
  return record;
}

/** The four analyses, as the readiness query returns them. */
interface Readiness {
  readonly funding: AnalysisView;
  readonly missingDocuments: AnalysisView;
  readonly beneficiaryConflicts: AnalysisView;
  readonly estateTax: AnalysisView;
}

const MFA_LEVEL_GQL: Record<MfaLevel, SessionPayload['mfaLevel']> = {
  none: 'NONE',
  mfa: 'MFA',
  stepup: 'STEPUP',
};

const OK = { ok: true } as const;

function cookieValue(ctx: RequestContext, name: string): string | null {
  return parseCookies(ctx.req.headers.cookie).get(name) ?? null;
}

function requireAccessToken(ctx: RequestContext): string {
  const token = cookieValue(ctx, ACCESS_COOKIE);
  if (token === null) {
    throw bffError('UNAUTHENTICATED');
  }
  return token;
}

export function createBffSchema(deps: SchemaDeps): GraphQLSchema {
  const { identity, assets, assistant, documents, secureCookies } = deps;
  const now = deps.now ?? ((): number => Date.now());

  return createSchema<RequestContext>({
    typeDefs,
    resolvers: {
      Query: {
        session: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<SessionPayload | null> => {
          const token = cookieValue(ctx, ACCESS_COOKIE);
          if (token === null) {
            return null;
          }
          const session = await identity.session(token);
          if (session === null) {
            return null;
          }
          const expiresAt =
            session.stepupExpiresAt === null ? Number.NaN : Date.parse(session.stepupExpiresAt);
          return {
            userId: session.userId,
            mfaLevel: MFA_LEVEL_GQL[session.mfaLevel],
            stepUpFresh: Number.isFinite(expiresAt) && expiresAt > now(),
          };
        },
        assets: async (_parent: unknown, _args: unknown, ctx: RequestContext): Promise<Asset[]> =>
          assets.list(requireAccessToken(ctx)),
        netWorth: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<NetWorth> => assets.netWorth(requireAccessToken(ctx)),
        // The four analyses run CONCURRENTLY and independently: each carries
        // its own status, so a peer blinking during one of them costs that
        // card and not the page. `Promise.all` rather than `allSettled`
        // because the client already turns every non-401 downstream failure
        // into a status — what still rejects is UNAUTHENTICATED, which is a
        // fact about the whole request and should surface as one.
        readiness: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<Readiness> => {
          const token = requireAccessToken(ctx);
          const names: readonly AnalysisName[] = [
            'funding',
            'missing-documents',
            'beneficiary-conflicts',
            'estate-tax',
          ];
          const [funding, missingDocuments, beneficiaryConflicts, estateTax] = await Promise.all(
            names.map((name) => assistant.analysis(token, name)),
          );
          return {
            funding: funding as AnalysisView,
            missingDocuments: missingDocuments as AnalysisView,
            beneficiaryConflicts: beneficiaryConflicts as AnalysisView,
            estateTax: estateTax as AnalysisView,
          };
        },
        consents: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<string[]> => assistant.consents(requireAccessToken(ctx)),
        conversations: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<Conversation[]> => assistant.conversations(requireAccessToken(ctx)),
        conversation: async (
          _parent: unknown,
          args: ConversationArgs,
          ctx: RequestContext,
        ): Promise<Transcript> =>
          assistant.transcript(requireAccessToken(ctx), args.conversationId),
        documentTemplates: async (
          _parent: unknown,
          args: { readonly state: string },
          ctx: RequestContext,
        ): Promise<DocumentTemplate[]> => documents.templates(requireAccessToken(ctx), args.state),
        documents: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<Document[]> => documents.list(requireAccessToken(ctx)),
        document: async (
          _parent: unknown,
          args: DocumentArgs,
          ctx: RequestContext,
        ): Promise<Document> => documents.get(requireAccessToken(ctx), args.documentId),
        documentVersions: async (
          _parent: unknown,
          args: DocumentArgs,
          ctx: RequestContext,
        ): Promise<DocumentVersion[]> =>
          documents.versions(requireAccessToken(ctx), args.documentId),
        // One audited decrypt per call. There is deliberately no field on
        // Document that resolves content, and no list variant of this: a
        // convenience that let a page render N documents' text would turn one
        // page load into N decrypt events on the user's own audit trail.
        documentContent: async (
          _parent: unknown,
          args: DocumentArgs & { readonly version: number },
          ctx: RequestContext,
        ): Promise<DocumentContent> =>
          documents.content(requireAccessToken(ctx), args.documentId, args.version),
      },
      Mutation: {
        register: async (
          _parent: unknown,
          args: CredentialsArgs,
          _ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.register(args.email, args.password);
          return OK;
        },
        login: async (
          _parent: unknown,
          args: CredentialsArgs,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          const tokens = await identity.login(args.email, args.password);
          setSessionCookies(ctx.res, tokens, secureCookies);
          return OK;
        },
        refresh: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          const refreshToken = cookieValue(ctx, REFRESH_COOKIE);
          if (refreshToken === null) {
            throw bffError('UNAUTHENTICATED');
          }
          const tokens = await identity.refresh(refreshToken);
          setSessionCookies(ctx.res, tokens, secureCookies);
          return OK;
        },
        logout: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          // Revoke server-side FIRST — the cookies are the only copies of the
          // tokens, so clearing them before a failed revocation would strand a
          // live session that only a thief could still use.
          //
          // TWO CREDENTIALS, because they expire on different clocks. The
          // access token lasts 15 minutes and the refresh token 30 days, so
          // any tab older than the access TTL cannot revoke through the
          // guarded route — identity answers 401. Treating that 401 as success
          // was the M8-review finding: it revoked nothing, cleared the
          // cookies, and reported "signed out" over a session that remained
          // valid for up to a month. So a dead access token falls through to
          // the refresh credential rather than being read as done.
          const accessToken = cookieValue(ctx, ACCESS_COOKIE);
          const refreshToken = cookieValue(ctx, REFRESH_COOKIE);
          let revoked = false;
          if (accessToken !== null) {
            revoked = await identity.logout(accessToken);
          }
          if (!revoked && refreshToken !== null) {
            await identity.logoutByRefresh(refreshToken);
            revoked = true;
          }
          // Cookies are cleared when the session is genuinely gone, or when
          // there was no credential to revoke in the first place (already
          // signed out — clearing is then just tidying). Never after a
          // revocation we could not complete: that path throws above.
          clearSessionCookies(ctx.res, secureCookies);
          return OK;
        },
        createAsset: async (
          _parent: unknown,
          args: {
            category: string;
            title: string;
            estValue?: string | null;
            valuationAsOf?: string | null;
            valuationSource?: string | null;
          },
          ctx: RequestContext,
        ): Promise<CreateResult> => {
          // Reject a PARTIAL valuation here rather than forwarding it: the
          // ledger would refuse it anyway, and a stable INVALID_REQUEST is a
          // better answer than a masked downstream 400.
          const parts = [args.estValue, args.valuationAsOf, args.valuationSource].filter(
            (part): part is string => typeof part === 'string' && part.length > 0,
          );
          if (parts.length !== 0 && parts.length !== 3) {
            throw bffError('INVALID_REQUEST');
          }
          return assets.create(requireAccessToken(ctx), {
            category: args.category,
            title: args.title,
            ...(parts.length === 3
              ? {
                  valuation: {
                    estValue: parts[0] as string,
                    valuationAsOf: parts[1] as string,
                    valuationSource: parts[2] as string,
                  },
                }
              : {}),
          });
        },
        startConversation: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<Conversation> => assistant.startConversation(requireAccessToken(ctx)),
        sendMessage: async (
          _parent: unknown,
          args: ConversationArgs & { readonly text: string },
          ctx: RequestContext,
        ): Promise<Turn> =>
          assistant.sendMessage(requireAccessToken(ctx), args.conversationId, args.text),
        deleteConversation: async (
          _parent: unknown,
          args: ConversationArgs,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await assistant.deleteConversation(requireAccessToken(ctx), args.conversationId);
          return OK;
        },
        generateDocument: async (
          _parent: unknown,
          args: {
            docType: string;
            state: string;
            templateId?: string | null;
            title?: string | null;
            variables: readonly DocumentVariableInput[];
          },
          ctx: RequestContext,
        ): Promise<GenerateResult> =>
          documents.generate(requireAccessToken(ctx), {
            docType: args.docType,
            state: args.state,
            ...(typeof args.templateId === 'string' ? { templateId: args.templateId } : {}),
            ...(typeof args.title === 'string' && args.title.length > 0
              ? { title: args.title }
              : {}),
            variables: intakeRecord(args.variables),
          }),
        regenerateDocument: async (
          _parent: unknown,
          args: DocumentArgs & {
            templateId?: string | null;
            title?: string | null;
            variables: readonly DocumentVariableInput[];
          },
          ctx: RequestContext,
        ): Promise<GenerateResult> =>
          documents.regenerate(requireAccessToken(ctx), args.documentId, {
            ...(typeof args.templateId === 'string' ? { templateId: args.templateId } : {}),
            ...(typeof args.title === 'string' && args.title.length > 0
              ? { title: args.title }
              : {}),
            variables: intakeRecord(args.variables),
          }),
        grantConsent: async (
          _parent: unknown,
          args: ScopeArgs,
          ctx: RequestContext,
        ): Promise<string[]> => assistant.grantConsent(requireAccessToken(ctx), args.scope),
        revokeConsent: async (
          _parent: unknown,
          args: ScopeArgs,
          ctx: RequestContext,
        ): Promise<string[]> => assistant.revokeConsent(requireAccessToken(ctx), args.scope),
        totpEnroll: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<{ otpauthUri: string }> => {
          return identity.totpEnroll(requireAccessToken(ctx));
        },
        totpVerify: async (
          _parent: unknown,
          args: CodeArgs,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.totpVerify(requireAccessToken(ctx), args.code);
          return OK;
        },
        stepUp: async (
          _parent: unknown,
          args: CodeArgs,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.stepUp(requireAccessToken(ctx), args.code);
          return OK;
        },
        exportDemo: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.exportDemo(requireAccessToken(ctx));
          return OK;
        },
      },
    },
  });
}
