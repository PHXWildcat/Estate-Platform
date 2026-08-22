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
 * the string literals and drift away from the fence that governs them
 * (`packages/auth-guard/test/session-audience.spec.ts`, which pins this union
 * to identity's DDL in both directions).
 *
 * `account` is the ordinary session every flow uses. `vault` is minted only by
 * identity's handoff redemption for the isolated vault origin, carries no
 * refresh token, and lives 15 minutes (docs/03 §6i). `extension` is minted by
 * the M16 pairing ceremony for the browser extension; unlike `vault` it DOES
 * carry a refresh token, which is why it is admitted per handler to a set that
 * yields ciphertext and cannot destroy anything (docs/03 §6j).
 *
 * `operator` is minted by the SAME handoff ceremony as `vault` (M21 PR3a), for
 * the isolated operator origin, and is the one audience whose value is PURELY
 * subtractive: it is admitted by no service at all, only by identity's three
 * self-referential routes, so holding one is strictly LESS than holding the
 * account session it was minted from.
 *
 * THAT IS WHY MINTING IT IS ROLE-BLIND AND SAFE. Identity cannot ask whether
 * the caller is an operator — it holds no settlement credential, there is no
 * dblink between the auth and core clusters, and it has no concept of a role —
 * so any account holder may mint one under step-up. Nothing is granted by
 * doing so. `settlement_operators`, read through `OperatorGate`, remains the
 * only thing that decides who may act on a death case, exactly as before the
 * audience existed. An audience is a RESTRICTION on where a credential may be
 * spent, never a claim about who is holding it.
 */
export const SESSION_AUDIENCES = ['account', 'vault', 'extension', 'operator'] as const;
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

/**
 * Why a login was refused, as recorded on `estate.auth.events.v1` and in the
 * audit trail. NAMED rather than inline so identity's own signatures derive
 * from this enum instead of restating it — a second spelling of a closed
 * vocabulary is a second thing to forget to widen.
 */
// 'account_settled': correct password against an account in settlement
// status (M7) — either the verification was wrong or the decedent's
// credentials are being replayed; a detection-worthy signal either way.
//
// 'account_closed' (M25 PR3) is SPLIT OUT of it, because 'closed' used to
// ride along with 'settlement' here and now has a second, entirely
// different cause: an account the OWNER erased. Two failures needing
// different remedies must not share a token — one is a detection signal
// about a possible decedent-credential replay, the other is a person
// signing in to an account they deliberately destroyed, and an analyst who
// cannot tell them apart will investigate the wrong one.
//
// REACHABLE ONLY IN THE WINDOW WHERE ERASURE HALF-HAPPENED, which is the
// window worth naming. A completed erasure re-indexes `email_bidx`, so the
// address no longer resolves to a row and login stops before any status is
// read. This token fires when the account was closed but the process did
// not get as far as the address — exactly the state an operator needs to
// find, and one that would otherwise be filed as a settlement anomaly.
export const LoginFailureReasonSchema = z.enum([
  'bad_credentials',
  'account_locked',
  'risk_blocked',
  'account_settled',
  'account_closed',
]);

export type LoginFailureReason = z.infer<typeof LoginFailureReasonSchema>;

export const LoginFailedEvent = defineEvent(
  'auth.login.failed',
  1,
  z.object({
    // null when the identifier did not resolve to a user; we never echo the
    // attempted identifier itself.
    userId: z.string().uuid().nullable(),
    reason: LoginFailureReasonSchema,
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
