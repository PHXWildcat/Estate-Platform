import { z } from 'zod';
import { defineEvent } from './envelope';

/** Session assurance levels, mirroring auth.sessions.mfa_level (docs/02 §1). */
export const MfaLevelSchema = z.enum(['none', 'mfa', 'stepup']);
export type MfaLevel = z.infer<typeof MfaLevelSchema>;

/**
 * WHAT A SESSION MAY BE SPENT ON, mirroring auth.sessions.audience (M15).
 *
 * The VOCABULARY lives here and the ENFORCEMENT lives in @estate/auth-guard,
 * because they have different consumers. Three things need to agree on this
 * list: identity's `CHECK (audience IN (…))`, `CallerGuard`'s deny-by-default
 * admission, and the BFF — which labels sessions with it and deliberately does
 * NOT depend on auth-guard, since a NestJS guard package has no business inside
 * the edge. `MfaLevelSchema` directly above is the same shape for the same
 * reason and is imported by both auth-guard and the BFF today.
 *
 * ONE SOURCE, so a consumer that cannot import auth-guard cannot hand-copy
 * three string literals and drift away from the fence that governs them
 * (`packages/auth-guard/test/session-audience.spec.ts`, which pins this union
 * to identity's DDL in both directions).
 *
 * `account` is the ordinary session every flow uses. `vault` is minted only by
 * identity's handoff redemption for the isolated vault origin, carries no
 * refresh token, and lives 15 minutes (docs/03 §6i). `extension` is minted by
 * the M16 pairing ceremony for the browser extension; unlike `vault` it DOES
 * carry a refresh token, which is why it is admitted per handler to a set that
 * yields ciphertext and cannot destroy anything (docs/03 §6j).
 */
export const SESSION_AUDIENCES = ['account', 'vault', 'extension'] as const;
export const SessionAudienceSchema = z.enum(SESSION_AUDIENCES);
export type SessionAudience = z.infer<typeof SessionAudienceSchema>;

/**
 * What a session is when nothing says otherwise, and what an ABSENT `audience`
 * on the introspection response means.
 *
 * Sound rather than lax: a non-`account` audience can only exist because
 * identity minted one, and an identity old enough to omit the field has no
 * route that mints one. An UNRECOGNISED value is a different matter and fails
 * closed — see the verifier's enum.
 *
 * Typed as the LITERAL rather than widened to `SessionAudience`, so that
 * `audience === DEFAULT_SESSION_AUDIENCE` narrows the other branch to the
 * non-default audiences. `satisfies` keeps the membership check that the
 * explicit annotation used to provide, without throwing away which member it
 * is. The fence that walks the audience tables needs exactly that narrowing.
 */
export const DEFAULT_SESSION_AUDIENCE = 'account' satisfies SessionAudience;

export const UserRegisteredEvent = defineEvent(
  'auth.user.registered',
  1,
  z.object({ userId: z.string().uuid() }),
);

export const LoginSucceededEvent = defineEvent(
  'auth.login.succeeded',
  1,
  z.object({
    userId: z.string().uuid(),
    sessionId: z.string().uuid(),
    mfaLevel: MfaLevelSchema,
  }),
);

export const LoginFailedEvent = defineEvent(
  'auth.login.failed',
  1,
  z.object({
    // null when the identifier did not resolve to a user; we never echo the
    // attempted identifier itself.
    userId: z.string().uuid().nullable(),
    // 'account_settled': correct password against an account in settlement
    // status (M7) — either the verification was wrong or the decedent's
    // credentials are being replayed; a detection-worthy signal either way.
    reason: z.enum(['bad_credentials', 'account_locked', 'risk_blocked', 'account_settled']),
  }),
);

export const StepUpGrantedEvent = defineEvent(
  'auth.stepup.granted',
  1,
  z.object({
    userId: z.string().uuid(),
    sessionId: z.string().uuid(),
    method: z.enum(['totp', 'webauthn']),
    expiresAt: z.string().datetime(), // ≤5-minute freshness window
  }),
);

export const SessionRevokedEvent = defineEvent(
  'auth.session.revoked',
  1,
  z.object({
    userId: z.string().uuid(),
    sessionId: z.string().uuid(),
    reason: z.enum(['logout', 'expired', 'admin', 'risk', 'rotation_reuse_detected']),
  }),
);

export const AuthEventSchema = z.discriminatedUnion('type', [
  UserRegisteredEvent,
  LoginSucceededEvent,
  LoginFailedEvent,
  StepUpGrantedEvent,
  SessionRevokedEvent,
]);
export type AuthEvent = z.infer<typeof AuthEventSchema>;
