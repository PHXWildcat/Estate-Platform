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
  const { identity, assets, assistant, secureCookies } = deps;
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
