import type { MfaLevel } from '../graphql/client';

/**
 * WHAT A SESSION FIELD MEASURES, said once (M24 PR4).
 *
 * `mfaLevel` is the FACTOR LEVEL OF THIS SESSION — how the person holding this
 * credential authenticated — and it is NOT a fact about what the account has
 * enrolled. `AuthService.login` never asks for a factor: every fresh sign-in
 * starts at `NONE`, including one by an account holding TOTP and three
 * passkeys, until something steps it up. So "MFA not enrolled" is false of the
 * account exactly when the account is at its most protected and its owner has
 * simply not stepped up yet.
 *
 * This wording has now been wrong TWICE on the same field. In M20 the union
 * itself was lowercase, making every comparison permanently false, and a live
 * account with no `mfa_methods` row was shown "MFA enrolled"; the enum was
 * fixed and the WORDING was left. The M24 PR3 drive found the same sentence
 * still on `SessionCard` and corrected it on the dashboard — and PR4's review
 * found /security, the older and larger consumer, still saying it. A second
 * copy is a copy that drifts, so the chips live here and both surfaces render
 * these and nothing else. `session-wording.test.ts` scans the component corpus
 * for the account-claiming spellings and fails on a re-introduction.
 */
export interface SessionChip {
  readonly label: string;
  readonly className: string;
}

/**
 * How this session authenticated. Never "enrolled"/"not enrolled" — the app
 * cannot see the account's factor set from `session`, and the one surface that
 * needs to act on it (adding a factor) learns it from the server's own refusal
 * rather than from a guess rendered before the ask.
 */
export function factorChip(mfaLevel: MfaLevel): SessionChip {
  return mfaLevel === 'NONE'
    ? { label: 'Password-only session', className: 'chip chip-warn' }
    : { label: 'Second factor verified', className: 'chip chip-success' };
}

/**
 * Whether a step-up is still fresh. This one IS a session fact in both the
 * value and the wording, and it decays by CLOCK — which is why no cache may
 * hold it (docs/03 §6ss) and why the chip is rendered from a live read.
 */
export function stepUpChip(stepUpFresh: boolean): SessionChip {
  return stepUpFresh
    ? { label: 'Step-up fresh', className: 'chip chip-success' }
    : { label: 'Step-up not fresh', className: 'chip' };
}
