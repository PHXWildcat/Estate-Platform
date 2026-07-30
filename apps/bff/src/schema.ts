import type { IncomingMessage, ServerResponse } from 'node:http';
import type { GraphQLSchema } from 'graphql';
import { createSchema } from 'graphql-yoga';
import type { MfaLevel } from '@estate/contracts';
import type { Asset, AssetsClient, CreateResult, NetWorth } from './assets-client';
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

  type Query {
    "Current session, or null when unauthenticated."
    session: Session
    "The caller's assets. The BFF forwards the caller's own bearer token."
    assets: [Asset!]!
    netWorth: NetWorth!
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
  const { identity, assets, secureCookies } = deps;
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
          // live session that only a thief could still use. A token identity
          // no longer recognizes is already logged out, not a failure.
          const token = cookieValue(ctx, ACCESS_COOKIE);
          if (token !== null) {
            await identity.logout(token);
          }
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
