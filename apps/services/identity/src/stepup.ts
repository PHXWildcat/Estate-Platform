// Step-up freshness now has ONE definition, in the shared PEP package: identity
// grants the elevation, every downstream StepUpGuard verifies it, so the ≤5-min
// rule (docs/01 §5) cannot drift between the two. Re-exported here so identity's
// existing call sites keep importing from './stepup'.
export { isStepUpFresh, STEPUP_WINDOW_MS } from '@estate/auth-guard';

/** Opaque access-token lifetime (short by design; refresh rotates). */
export const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;

/** Session / refresh-token lifetime. */
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
