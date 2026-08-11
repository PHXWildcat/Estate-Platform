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
  // ONE sentence for a wrong password and a wrong Secret Key alike — the 2SKD
  // rule the unlock screen shares with the server's single `srp_failed`.
  SRP_FAILED:
    'That didn’t open this vault. Check your vault password and your Secret Key — we can’t tell you which one was wrong.',
  STEPUP_REQUIRED: 'Estate needs a fresh identity check before this device can continue.',
  VAULT_LOCKED: 'Your vault is locked.',
  // The item moved under us. NOT phrased as a failure the user caused, and
  // deliberately not offering "overwrite anyway": the whole point of `If-Match`
  // is that the newer value is seen before it is replaced.
  VERSION_CONFLICT:
    'This item changed somewhere else since you opened it. Close this and open it again so you are editing the current version.',
  // Reached only if a create is retried after it already succeeded — the id is
  // client-generated, so the service treats the repeat as the same request.
  // `vault-screens` handles it as success; this sentence is the fallback for
  // anywhere that does not.
  ITEM_EXISTS: 'That item was already saved.',
  NOT_FOUND: 'That isn’t available.',
  UNAVAILABLE: 'Estate isn’t reachable right now. Nothing has changed — try again in a moment.',
  NETWORK: 'We couldn’t reach Estate. Check your connection and try again.',
  UNKNOWN: 'Something went wrong. Please try again in a moment.',
};

export function messageFor(code: ApiFailure): string {
  return messages[code];
}
