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
  // The assistant's uniform not-found. The copy is uniform too: it must not
  // hint that the conversation exists but belongs to someone else, which is the
  // oracle the service refuses to be (M11).
  NOT_FOUND: 'That conversation isn’t available.',
  // The one refusal the user can act on, so it says what to do.
  ASSISTANT_DISABLED: 'The assistant is switched off. Turn it on to continue.',
  NETWORK: 'We couldn’t reach the server. Check your connection and try again.',
  UNKNOWN: 'Something went wrong on our side. Please try again in a moment.',
};

export function messageFor(code: GqlFailureCode): string {
  return errorCopy[code];
}
