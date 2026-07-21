import type { IncomingMessage, ServerResponse } from 'node:http';
import type { GraphQLSchema } from 'graphql';
import { createSchema } from 'graphql-yoga';
import type { MfaLevel } from '@estate/contracts';
import { ACCESS_COOKIE, REFRESH_COOKIE, parseCookies, setSessionCookies } from './cookies';
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

  type Query {
    "Current session, or null when unauthenticated."
    session: Session
  }

  type Mutation {
    register(email: String!, password: String!): Ok!
    "Sets httpOnly session cookies; no token material in the response body."
    login(email: String!, password: String!): Ok!
    "Rotates the token pair using the refresh cookie; re-sets both cookies."
    refresh: Ok!
    totpEnroll: TotpEnroll!
    totpVerify(code: String!): Ok!
    stepUp(code: String!): Ok!
    "Step-up-gated demo action (stands in for data export)."
    exportDemo: Ok!
  }
`;

/** Server context wired by the express↔yoga integration in app.ts. */
export interface RequestContext {
  req: IncomingMessage;
  res: ServerResponse;
}

export interface SchemaDeps {
  identity: IdentityClient;
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
  const { identity, secureCookies } = deps;
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
