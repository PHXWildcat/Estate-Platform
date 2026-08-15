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
  // Not the user's mistake either, and not a failure: the platform can share
  // estate contacts and nothing else yet. Says so plainly rather than blaming
  // the request, and promises no date.
  GRANT_NOT_ENFORCED:
    'Estate can’t share that part of your plan yet — contacts are the only thing a role can be allowed to read today. Nothing was changed.',
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
  // M19 PR4 review. The ONLY sentence here whose remedy is to wait, so it is
  // the only one that must not say "try again" on its own: after the cap the
  // next code is refused however correct it is, and someone told to try again
  // concludes their authenticator is broken. It deliberately does not name a
  // number of minutes — that window is a reviewed constant in a service this
  // app cannot import, and a hard-coded figure here would drift out of a
  // sentence people plan around.
  TOO_MANY_ATTEMPTS:
    'Too many attempts. For your protection this is paused for a few minutes — wait, then try ' +
    'again. Nothing is wrong with your code or your account.',
  // M20 PR2. Deliberately says "asked for" and never "we sent you", because the
  // route this comes from does not promise delivery: an address that already
  // belongs to somebody else is answered identically and never mailed, so a
  // reader can meet this sentence with nothing in their inbox. "If a code
  // arrived" is the conditional that keeps it true either way.
  CODE_REQUESTED_RECENTLY:
    'You asked for this very recently. If a code arrived, use that one — otherwise wait a few ' +
    'minutes before asking again.',
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

/**
 * THE THIRD SURFACE on which `INVALID_CREDENTIALS` means something else (M20
 * PR1), and it is the same defect the M12 finding closed, one form over.
 *
 * On the password-change form the code means "the CURRENT password you typed
 * was wrong" — identity answers it from `verifyPassword`. The default wording,
 * "that email and password combination didn't work", names an email field this
 * form does not have and sends the reader to re-check an address that is not
 * the problem. There is no ambiguity to preserve here either: the caller is
 * already authenticated, so the refusal cannot be an account-existence oracle
 * and can safely say exactly which field was rejected.
 *
 * TOO_MANY_ATTEMPTS deliberately keeps its ordinary wording. It is reachable
 * here — M17's bound is per-session AND per-account — and the shared copy
 * already says to wait without naming a number of minutes, which is right,
 * because that window is a reviewed constant in a service this app cannot
 * import.
 */
export function passwordChangeMessageFor(code: GqlFailureCode): string {
  return code === 'INVALID_CREDENTIALS'
    ? 'That current password wasn’t right. Check it and try again — your password has not been changed.'
    : errorCopy[code];
}

/**
 * The address change is TWO forms and therefore TWO resolvers (M20 PR2), which
 * is the point rather than an inconvenience: `INVALID_REQUEST` means "check the
 * address you typed" on the request leg and "that code isn't a shape we accept"
 * on the completion leg, and one function serving both would have to pick a
 * sentence that is wrong on one of them. The M12 rule — a form must never
 * explain a refusal in the vocabulary of a field it does not have — applied to
 * a ceremony whose two halves have entirely different fields.
 *
 * REQUEST leg. `INVALID_CREDENTIALS` is the CURRENT password (identity answers
 * it from `verifyPassword`, exactly as on the password-change form), so the
 * default "email and password combination" wording names a field this form does
 * not have. `INVALID_REQUEST` is identity's answer to BOTH a malformed address
 * and one that is already this account's — it genuinely conflates them, so this
 * sentence names the actionable possibility without asserting which applied.
 *
 * Both sentences end by saying nothing changed, which is the fact a reader most
 * needs after a refusal on a route that rewrites where they sign in.
 */
export function addressChangeMessageFor(code: GqlFailureCode): string {
  if (code === 'INVALID_CREDENTIALS') {
    return 'That current password wasn’t right. Check it and try again — your sign-in address has not been changed.';
  }
  if (code === 'INVALID_REQUEST') {
    return 'We couldn’t start that change. Check the new address — if it’s the one you already sign in with, there’s nothing to change. Nothing has been changed.';
  }
  return errorCopy[code];
}

/**
 * COMPLETION leg (M20 PR2). Identity answers one `invalid_code` for every way a
 * challenge fails — unknown, expired, spent, cancelled, attempt-exhausted, and
 * a raced registration that took the address first — so the copy has to carry
 * the possibilities the server deliberately refuses to distinguish.
 *
 * The shared INVALID_VERIFICATION_CODE sentence (M14) would end "send yourself
 * a new one", which is the remedy on the address-VERIFICATION surface and is
 * not available here: there is no resend route for a pending change, and asking
 * for a fresh code means cancelling this one and starting again. Offering a
 * button that does not exist is how a stuck user stays stuck.
 */
export function addressCodeMessageFor(code: GqlFailureCode): string {
  return code === 'INVALID_VERIFICATION_CODE'
    ? 'That code wasn’t accepted. Codes are single-use, expire after a short while, and stop working once too many wrong ones are tried — cancel this change and start again to get a new one.'
    : errorCopy[code];
}
