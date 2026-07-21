import { z } from 'zod';
import { defineEvent } from './envelope';

/** Session assurance levels, mirroring auth.sessions.mfa_level (docs/02 §1). */
export const MfaLevelSchema = z.enum(['none', 'mfa', 'stepup']);
export type MfaLevel = z.infer<typeof MfaLevelSchema>;

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
    reason: z.enum(['bad_credentials', 'account_locked', 'risk_blocked']),
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
