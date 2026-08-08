import { SetMetadata, type CustomDecorator } from '@nestjs/common';
import { DEFAULT_SESSION_AUDIENCE, type SessionAudience } from '@estate/auth-guard';

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
 * `test/session-audience.spec.ts` checks against `VAULT_AUDIENCE_ROUTES` below.
 *
 * The three exceptions, and why each is safe rather than merely convenient:
 *
 *   · `GET /v1/auth/session` — introspection. It MUST admit every audience,
 *     because it is how the vault service resolves the vault-origin caller in
 *     the first place; refusing here would not tighten anything, it would make
 *     the audience unusable. It reports the audience rather than acting on it.
 *   · `POST /v1/auth/stepup` — a vault session must be able to re-prove a
 *     factor without a round trip back to the app origin. Step-up is a
 *     STRENGTHENING of the session presenting it and confers nothing beyond
 *     that session, so a vault session that steps up is still a vault session
 *     and still reaches only the vault service.
 *   · `POST /v1/auth/logout` — the vault origin's own sign-out. Revoking the
 *     credential you presented is the one action that can only ever reduce
 *     authority, and the M6 rule says the protective action must never be the
 *     harder one.
 *
 * What is deliberately NOT here is the rest of the surface, and one entry
 * matters more than the others: `POST /v1/auth/handoff` is account-only, so a
 * vault session cannot mint another handoff. Without that the audience would be
 * a speed bump — anyone holding a leaked vault session could chain a fresh one
 * indefinitely and, worse, a future second audience would be reachable from the
 * first. TOTP enrollment, WebAuthn registration, email verification and the
 * data export are account-only for the plainer reason that they change or
 * exercise account-level authority, which is not what the vault origin was
 * handed.
 */
export const SESSION_AUDIENCE_METADATA = 'estate:session-audiences';

/** Routes that admit a `vault` session, as data. Enforced, not descriptive. */
export const VAULT_AUDIENCE_ROUTES = ['session', 'stepUp', 'logout'] as const;

/**
 * Widen one route's admitted audiences. `account` is always implied — a route
 * that dropped it would be reachable from the vault origin and nowhere else,
 * which no route in this service wants and which would be a silent outage
 * rather than a control.
 */
export function AllowSessionAudiences(
  ...audiences: readonly Exclude<SessionAudience, 'account'>[]
): CustomDecorator<string> {
  return SetMetadata<string, readonly SessionAudience[]>(SESSION_AUDIENCE_METADATA, [
    DEFAULT_SESSION_AUDIENCE,
    ...audiences,
  ]);
}
