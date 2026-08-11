import type { ApiFailure } from './api.js';

/**
 * The only place a failure code becomes words.
 *
 * ONE SENTENCE FOR EVERY WAY A PAIRING CODE IS REFUSED, because identity
 * answers one `invalid_code` for unknown, expired, already spent, revoked,
 * mis-shaped and raced — and that uniformity IS the control. The copy carries
 * the possibilities the server deliberately refuses to distinguish, which is
 * the M14 rule: when the platform will not say which reason applied, the
 * sentence has to.
 *
 * `UNAUTHENTICATED` is kept apart from it. On this surface that means the
 * device's own session is gone — revoked from the owner's paired-devices list,
 * or expired — and the remedy is a fresh pairing code, not a retype. Telling
 * those two apart is not an oracle: they are facts about the caller's own
 * credential, not about somebody else's.
 */
export const messages: Record<ApiFailure, string> = {
  INVALID_CODE:
    'That code wasn’t accepted. Codes work once and expire after ten minutes — create a new one in Estate under Security.',
  UNAUTHENTICATED:
    'This device is no longer connected to your account. It may have been disconnected from Estate under Security. Connect it again to continue.',
  STEPUP_REQUIRED: 'Estate needs a fresh identity check before this device can continue.',
  VAULT_LOCKED: 'Your vault is locked.',
  NOT_FOUND: 'That isn’t available.',
  UNAVAILABLE: 'Estate isn’t reachable right now. Nothing has changed — try again in a moment.',
  NETWORK: 'We couldn’t reach Estate. Check your connection and try again.',
  UNKNOWN: 'Something went wrong. Please try again in a moment.',
};

export function messageFor(code: ApiFailure): string {
  return messages[code];
}
