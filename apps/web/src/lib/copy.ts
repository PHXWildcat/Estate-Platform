import type { GqlFailureCode } from '../graphql/client';

/**
 * The only place server failure codes become user-facing text. Messages are
 * deliberately generic: they must never reveal whether an account exists,
 * why credentials failed, or any server internals.
 */
export const errorCopy: Record<GqlFailureCode, string> = {
  INVALID_CREDENTIALS: 'That email and password combination didn’t work. Check both and try again.',
  UNAUTHENTICATED: 'Your session has ended. Please sign in again.',
  STEPUP_REQUIRED: 'For your security, this action needs a fresh identity check.',
  INVALID_REQUEST: 'Something about that request wasn’t right. Please review and try again.',
  // A UNIFORM not-found, and the copy is uniform too: it must not hint that the
  // thing exists but belongs to somebody else, which is the oracle the
  // assistant refuses to be (M11) and which the BFF narrows for documents by
  // answering this same code to a plain downstream 403 (M12). Deliberately
  // says neither "conversation" nor "document" — one sentence for both, because
  // a per-surface variant is how the distinction creeps back in.
  NOT_FOUND: 'That isn’t available.',
  // The one refusal the user can act on, so it says what to do.
  ASSISTANT_DISABLED: 'The assistant is switched off. Turn it on to continue.',
  // M12. Each of these is a distinct answer with a distinct remedy — which is
  // why the BFF kept them apart instead of collapsing them into one conflict.
  TEMPLATE_NOT_FOUND:
    'We don’t have an attorney-reviewed template for that document in that state yet.',
  CONTENT_ERASED:
    'This version’s contents were permanently erased. The record of it remains, but the text cannot be recovered.',
  VERSION_CONFLICT: 'This document changed since you opened it. Reload and try again.',
  DOCUMENT_NOT_EDITABLE:
    'This document has been signed, so its wording is now a legal record. Revoke or supersede it before creating a replacement.',
  NETWORK: 'We couldn’t reach the server. Check your connection and try again.',
  UNKNOWN: 'Something went wrong on our side. Please try again in a moment.',
};

export function messageFor(code: GqlFailureCode): string {
  return errorCopy[code];
}

/**
 * The same code means a different thing on a STEP-UP prompt, and one of them
 * was actively wrong (found by driving the real app in M12).
 *
 * Identity answers `invalid_credentials` for a rejected TOTP code exactly as it
 * does for a rejected password, so an inline step-up — the consent controls, the
 * document generator — told someone "that email and password combination didn't
 * work" about a form with neither an email nor a password on it. The remedy it
 * implies is to re-check credentials that are not the problem, while the actual
 * cause (a code that rolled over; codes last 30 seconds) goes unsaid.
 *
 * Everything else keeps its ordinary wording: only this one code changes
 * meaning with the surface.
 */
export function stepUpMessageFor(code: GqlFailureCode): string {
  return code === 'INVALID_CREDENTIALS'
    ? 'That code wasn’t accepted. Codes change every 30 seconds — check your authenticator app and enter the current one.'
    : errorCopy[code];
}
