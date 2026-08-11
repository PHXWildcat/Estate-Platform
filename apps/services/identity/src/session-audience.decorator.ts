import {
  AllowSessionAudiences,
  AUDIENCE_ROUTE_ADMITTERS,
  SESSION_AUDIENCE_METADATA,
  type SessionAudience,
} from '@estate/auth-guard';

/**
 * WHICH OF IDENTITY'S OWN ROUTES A NON-ACCOUNT SESSION MAY REACH (M15).
 *
 * Downstream services get one audience decision each, because a service is the
 * unit of authority there — `CallerGuard` reads
 * `ALLOWED_SESSION_AUDIENCES` once and applies it to everything it guards.
 * Identity cannot work that way. It is the one service every audience must
 * talk to at all (introspection is how a session becomes a caller anywhere),
 * while also owning the routes that MINT authority — so the decision here is
 * per route, and the default is the restrictive one.
 *
 * DENY BY DEFAULT: an undecorated route admits `account` alone. Widening is an
 * explicit decorator on a named handler, which is what
 * `test/session-audience.spec.ts` checks against `IDENTITY_AUDIENCE_ROUTES`
 * below.
 *
 * The three exceptions, and why each is safe rather than merely convenient.
 * M16 widened all three from `vault` to `vault` AND `extension`, and the
 * reasons did not need rewriting so much as generalizing — none of them was
 * ever about the vault in particular:
 *
 *   · `GET /v1/auth/session` — introspection. It MUST admit every audience,
 *     because it is how any service resolves a non-account caller in the first
 *     place; refusing here would not tighten anything, it would make the
 *     audience unusable. It reports the audience rather than acting on it.
 *   · `POST /v1/auth/stepup` — a non-account client must be able to prove a
 *     factor without a round trip back to the app origin. Step-up is a
 *     STRENGTHENING of the session presenting it and confers nothing beyond
 *     that session, so a session that steps up is still whatever audience it
 *     already was and still reaches only what that audience reaches. For the
 *     extension this is load-bearing rather than convenient: both SRP legs are
 *     step-up gated, so without it the extension could never open a vault.
 *   · `POST /v1/auth/logout` — sign-out. Revoking the credential you presented
 *     is the one action that can only ever reduce authority, and the M6 rule
 *     says the protective action must never be the harder one.
 *
 * What is deliberately NOT here is the rest of the surface, and one entry
 * matters more than the others: `POST /v1/auth/handoff` is account-only, so
 * NEITHER a vault session nor an extension session can mint one. Without that
 * the audience would be a speed bump — anyone holding a leaked non-account
 * session could chain a fresh one indefinitely, and one audience would become
 * reachable from another. TOTP enrollment, WebAuthn registration, email
 * verification and the data export are account-only for the plainer reason that
 * they change or exercise account-level authority, which is not what either
 * non-account client was handed.
 *
 * `POST /v1/auth/refresh` is absent for a different reason and it is worth
 * being precise about: it carries no guard at all, being unauthenticated by
 * construction (the refresh token is the authority), so there is no decorator
 * to place and nothing here to declare. The extension's long-lived credential
 * rides it, and what keeps that safe is not this table but the fact that
 * refresh ROTATES IN PLACE — the same session row, so its audience cannot
 * change — which has its own test rather than being left to the shape of an
 * UPDATE's SET list.
 */
/**
 * Re-exported, NOT redeclared: @estate/auth-guard owns the key so identity's
 * SessionGuard and every downstream CallerGuard read the same metadata. Two
 * guards with two copies of a string is how a route ends up decorated for a
 * key nobody checks.
 */
export { AllowSessionAudiences, SESSION_AUDIENCE_METADATA };

/**
 * This service's routes that admit a NON-ACCOUNT session, and which audiences
 * each admits — DERIVED from the shared table rather than restated.
 *
 * M15 PR3 unified the vocabulary: `@AllowSessionAudiences` and its metadata key
 * now live in @estate/auth-guard, so one fence there sees every widening in the
 * repo. Keeping a second hand-written list here would be a second place for the
 * same fact, free to disagree with the one the shared fence checks — the exact
 * drift shape this repo keeps finding. Identity's own spec still runs, against
 * this service's real controllers, so both the derivation and the decorators
 * stay pinned.
 *
 * A MAP rather than M15's flat `VAULT_AUDIENCE_ROUTES` array, because with a
 * second audience the question stopped being "does this route admit anything
 * unusual" and became "exactly which". A route that gained `extension` when it
 * should only have had `vault` would have passed the old shape, since it only
 * knew route names.
 */
const IDENTITY_PREFIX = 'identity:';

function deriveIdentityAudienceRoutes(): ReadonlyMap<string, readonly SessionAudience[]> {
  const routes = new Map<string, SessionAudience[]>();
  for (const [audience, keys] of Object.entries(AUDIENCE_ROUTE_ADMITTERS)) {
    for (const key of keys) {
      if (!key.startsWith(IDENTITY_PREFIX)) continue;
      const route = key.slice(IDENTITY_PREFIX.length);
      const admitted = routes.get(route) ?? [];
      admitted.push(audience as SessionAudience);
      routes.set(route, admitted);
    }
  }
  return routes;
}

export const IDENTITY_AUDIENCE_ROUTES = deriveIdentityAudienceRoutes();
