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
  // Surface-neutral on purpose (M19): the same stale-If-Match refusal now
  // covers documents AND assets, and the remedy is identical — re-read, then
  // decide again. Never auto-retry over someone else's newer change.
  VERSION_CONFLICT: 'This changed since you opened it. Reload to see the latest, then try again.',
  // The one refusal fixed by choosing a different number: the shares already
  // designated plus this one would pass 100% for that class.
  SHARE_SUM_EXCEEDED:
    'Those shares would add past 100%. Lower this share, or reduce another designation first.',
  DOCUMENT_NOT_EDITABLE:
    'This document has been signed, so its wording is now a legal record. Revoke or supersede it before creating a replacement.',
  // M12 PR2. The three upload refusals all mean the same thing about storage —
  // nothing was written anywhere — and three different things to the person
  // holding the file, which is why they are three sentences and not one.
  LEGAL_HOLD:
    'This document is being preserved as part of an estate matter, so it can’t be deleted right now.',
  INVALID_TRANSITION:
    'That isn’t the next step for this document. Refresh to see where it currently stands.',
  MALWARE_DETECTED:
    'Our scanner flagged that file as malicious, so we didn’t store it. If someone sent it to you, treat it with suspicion.',
  UNSUPPORTED_CONTENT:
    'We couldn’t accept that file. We take PDFs and scans (PNG, JPEG, TIFF) up to 10 MB, and the file has to genuinely be one of those. Nothing was stored.',
  SCAN_UNAVAILABLE:
    'We couldn’t check that file for malware, so we didn’t store it. Please try again in a few minutes.',
  // M13. Actionable, and deliberately not softened into a generic conflict:
  // the person needs to know that a designation stands in the way, because
  // deleting a contact used to retire its fiduciary roles silently.
  CONTACT_IN_USE:
    'This person still holds a role in your estate. Remove their roles first, then you can delete them.',
  ALREADY_LINKED:
    'This person already has an account linked to them. Remove that link first if you need to invite someone else.',
  // ONE sentence for every reason a code fails — unknown, expired, already used,
  // withdrawn. Telling them apart would confirm to whoever is holding a guess
  // that it named something real, so the remedy offered is the safe one: ask
  // for a new code. The cost is a vaguer message for an honest user.
  INVALID_LINK_CODE:
    'That code wasn’t accepted. Codes are single-use and expire after seven days — ask for a fresh one.',
  NOTIFICATIONS_UNAVAILABLE:
    'We can’t reach the owner to tell them about this right now, so we haven’t made the change. Please try again shortly.',
  // The two "already done" conflicts. Neither is the user's mistake — a double
  // click or a retry reaches them — so the copy states the outcome and stops.
  ROLE_ALREADY_GRANTED: 'This person already holds that exact role in your estate.',
  PERMISSION_ALREADY_GRANTED: 'That role is already allowed to read that.',
  // M14. Says WHY a code stops working, because the platform deliberately
  // refuses to say WHICH reason applied — one uniform answer is the control,
  // so the copy has to carry the possibilities instead of the server.
  INVALID_VERIFICATION_CODE:
    'That code didn’t work. Codes expire after a short while and can only be used once — send yourself a new one and try again.',
  // M15. The vault is where a vague failure is least acceptable: a user bounced
  // on the way in needs to know it was the platform rather than their
  // credentials, or the reasonable conclusion is that they have been locked out
  // of the most valuable thing they keep here.
  VAULT_UNAVAILABLE:
    'We couldn’t open the vault just now. Nothing about your vault has changed — please try again in a moment.',
  VERIFICATION_UNAVAILABLE: 'We couldn’t confirm that address just now. Please try again shortly.',
  // M16. Says what did NOT happen, because the alternative reading — that a
  // code was created and lost — would have someone waiting for one, or
  // wondering whether a stranger now holds it.
  PAIRING_UNAVAILABLE:
    'We couldn’t create a pairing code just now. No code was created — try again in a moment.',
  WEBAUTHN_FAILED:
    'That passkey wasn\u2019t accepted. Try again — and if it keeps failing, the passkey may be ' +
    'registered to a different account, or it may have been removed from this one.',
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
