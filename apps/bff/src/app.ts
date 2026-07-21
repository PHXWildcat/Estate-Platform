import type { IncomingMessage, ServerResponse } from 'node:http';
import { Module, type INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { GraphQLError, type FieldNode, type ValidationContext } from 'graphql';
import { createYoga, type Plugin } from 'graphql-yoga';
import { usePersistedOperations } from '@graphql-yoga/plugin-persisted-operations';
import type { BffConfig } from './config';
import type { IdentityClient } from './identity-client';
import { loadPersistedManifest, type PersistedOperationsManifest } from './persisted';
import { createBffSchema, type RequestContext } from './schema';

/**
 * GraphQL hardening status (Milestone 1):
 * - Persisted operations only in production (the dominant control: the
 *   executable surface is exactly the reviewed manifest).
 * - Introspection additionally blocked in production via a validation rule
 *   (defense in depth for manifest mistakes).
 * - Error masking on: clients never see stack traces or internal messages.
 * - TODO (tracked in README): depth/complexity limits and rate limiting —
 *   persisted-ops-only already bounds the query surface for M1.
 */

@Module({})
class AppModule {}

type ExpressHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  next: (err?: unknown) => void,
) => void;

interface ExpressLike {
  post(path: string, ...handlers: ExpressHandler[]): unknown;
}

/**
 * CSRF defense. The session cookies are SameSite=Strict, which is the primary
 * defense: browsers do not attach them to cross-site requests. This custom
 * header is the second layer for legacy/edge cases (old browsers, subdomain
 * takeover of a sibling site, plugins): a cross-site attacker cannot set a
 * custom header without a CORS preflight, which the BFF does not answer.
 * Requests without `x-estate-csrf: 1` are rejected before GraphQL executes,
 * with a generic body.
 */
const CSRF_HEADER = 'x-estate-csrf';

const csrfGuard: ExpressHandler = (req, res, next) => {
  if (req.headers[CSRF_HEADER] !== '1') {
    res.statusCode = 403;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ error: 'forbidden' }));
    return;
  }
  next();
};

/** Blocks __schema/__type in production (see hardening notes above). */
function useBlockIntrospection(): Plugin {
  return {
    onValidate({ addValidationRule }): void {
      addValidationRule((context: ValidationContext) => ({
        Field(node: FieldNode): void {
          if (node.name.value === '__schema' || node.name.value === '__type') {
            context.reportError(new GraphQLError('GraphQL introspection is disabled'));
          }
        },
      }));
    },
  };
}

export interface BffAppOptions {
  config: BffConfig;
  identity: IdentityClient;
  /** Injectable for tests; defaults to loading from PERSISTED_MANIFEST_PATH. */
  persistedOperations?: PersistedOperationsManifest;
  /** Nest logger override (tests pass false). */
  logger?: false;
}

/**
 * Composes the BFF: a NestJS express app with graphql-yoga mounted at
 * POST /graphql behind the CSRF guard. Returned app is not yet listening —
 * call `app.listen(port)` (main.ts) or `app.init()` (tests/supertest).
 */
export async function createBffApp(options: BffAppOptions): Promise<INestApplication> {
  const { config, identity } = options;
  const production = config.nodeEnv === 'production';
  const manifest =
    options.persistedOperations ?? loadPersistedManifest(config.persistedManifestPath);

  const yoga = createYoga<RequestContext>({
    schema: createBffSchema({ identity, secureCookies: production }),
    graphqlEndpoint: '/graphql',
    // POST-only mount + no GraphiQL/landing page: nothing to render in a browser.
    graphiql: false,
    landingPage: false,
    // Non-GraphQLError exceptions become a generic message; nothing internal
    // (and no PII/tokens — see identity-client.ts) ever reaches the client.
    maskedErrors: true,
    logging: false,
    plugins: [
      usePersistedOperations<RequestContext>({
        // Standard APQ-style client protocol: extensions.persistedQuery.sha256Hash.
        getPersistedOperation: (key: string): string | null => manifest.get(key) ?? null,
        allowArbitraryOperations: !production,
        customErrors: {
          // Generic on purpose: reveal neither manifest state nor why a hash failed.
          notFound: 'Operation not allowed',
          persistedQueryOnly: 'Operation not allowed',
          keyNotFound: 'Operation not allowed',
        },
      }),
      ...(production ? [useBlockIntrospection()] : []),
    ],
  });

  // bodyParser: false — yoga must consume the raw request stream itself.
  const app = await NestFactory.create(AppModule, {
    bodyParser: false,
    logger: options.logger ?? ['error', 'warn'],
  });

  // getInstance() is untyped (any) at the HttpServer interface; narrow to the
  // minimal surface we use.
  const express = app.getHttpAdapter().getInstance() as ExpressLike;
  express.post('/graphql', csrfGuard, (req, res) => {
    // Express req/res extend node's IncomingMessage/ServerResponse; yoga
    // receives them as its server context, so resolvers read cookies from
    // ctx.req and set cookies on ctx.res (see schema.ts / cookies.ts).
    void yoga(req, res, { req, res });
  });

  return app;
}
