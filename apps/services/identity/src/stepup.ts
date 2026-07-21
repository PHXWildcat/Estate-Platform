import type { MfaLevel } from '@estate/contracts';

/** Step-up freshness window: docs/01 §5 mandates "fresh, ≤5 min". */
export const STEPUP_WINDOW_MS = 5 * 60 * 1000;

/** Opaque access-token lifetime (short by design; refresh rotates). */
export const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;

/** Session / refresh-token lifetime. */
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * The step-up gate: a session may perform a sensitive action only while its
 * mfa_level is 'stepup' AND the freshness window has not lapsed.
 */
export function isStepUpFresh(
  mfaLevel: MfaLevel,
  stepupExpiresAt: Date | null,
  now: Date,
): boolean {
  return (
    mfaLevel === 'stepup' && stepupExpiresAt !== null && stepupExpiresAt.getTime() > now.getTime()
  );
}
