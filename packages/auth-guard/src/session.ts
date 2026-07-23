import type { MfaLevel } from '@estate/contracts';

/**
 * The verified session context a downstream service acts on. Mirrors the shape
 * identity's own SessionGuard attaches and its `GET /v1/auth/session`
 * introspection route returns — the single source of truth for "who is calling
 * and how strongly are they authenticated".
 */
export interface SessionContext {
  userId: string;
  sessionId: string;
  mfaLevel: MfaLevel;
  /** Non-null ⇒ a step-up is active until this instant (docs/01 §5, ≤5 min). */
  stepupExpiresAt: Date | null;
}

/** Injectable clock so step-up freshness is testable without real time. */
export type Clock = () => Date;

/** Step-up freshness window: docs/01 §5 mandates "fresh, ≤5 min". */
export const STEPUP_WINDOW_MS = 5 * 60 * 1000;

/**
 * The step-up gate: a session may perform a sensitive action only while its
 * mfa_level is 'stepup' AND the freshness window has not lapsed. Shared by
 * identity (which grants step-up) and every downstream StepUpGuard (which
 * verifies it), so the ≤5-minute rule has exactly one definition.
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
