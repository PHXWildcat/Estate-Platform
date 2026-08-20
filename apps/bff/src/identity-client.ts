import { GraphQLError } from 'graphql';
import { z } from 'zod';
import {
  DEFAULT_SESSION_AUDIENCE,
  MfaLevelSchema,
  SessionAudienceSchema,
  type MfaLevel,
  type SessionAudience,
} from '@estate/contracts';

/**
 * Client for the identity service's internal REST API (apps/services/identity).
 *
 * Error handling contract: identity's generic machine-readable error tokens
 * are mapped onto a small set of GraphQL error codes. Raw identity response
 * text is NEVER forwarded to GraphQL clients — unknown/5xx responses become a
 * plain Error, which yoga's maskedErrors turns into a generic message.
 */

export interface IssuedTokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly sessionId: string;
  readonly userId: string;
}

export interface IdentitySession {
  readonly userId: string;
  readonly sessionId: string;
  readonly mfaLevel: MfaLevel;
  /** ISO timestamp, or null when the session has no active step-up. */
  readonly stepupExpiresAt: string | null;
  /**
   * What the session may be spent on (M15's audience, carried in M16).
   *
   * Identity has RETURNED this since M15 and the BFF silently dropped it:
   * `z.object` strips unknown keys, so there was no parse error, no log and no
   * failing test — "the BFF has no audience" read like a missing identity field
   * when it was a missing line in one schema. It matters now because a session
   * list has to be able to say "browser extension" rather than "a session".
   */
  readonly audience: SessionAudience;
}

export interface TotpEnrollment {
  readonly otpauthUri: string;
}

/**
 * Whether the platform can PROVE it reaches this user (M14).
 *
 * Three states, not two, because `unavailable` is a fact about the platform
 * rather than about the user: telling somebody "your address is unverified"
 * during a notifications outage would send them to complete a ceremony that
 * cannot run, and telling them nothing at all would leave the arming gates
 * refusing with no explanation.
 */
export type EmailVerificationStatus = 'verified' | 'unverified' | 'unavailable';

/** What a resend attempt did — reported honestly rather than always "sent". */
export type ResendOutcome = 'sent' | 'too_soon' | 'already_verified' | 'unavailable';

export interface IdentityClient {
  register(email: string, password: string): Promise<void>;
  login(email: string, password: string): Promise<IssuedTokens>;
  refresh(refreshToken: string): Promise<IssuedTokens>;
  /** Returns null when the access token is invalid/expired (identity 401). */
  session(accessToken: string): Promise<IdentitySession | null>;
  totpEnroll(accessToken: string): Promise<TotpEnrollment>;
  totpVerify(accessToken: string, code: string): Promise<void>;
  stepUp(accessToken: string, code: string): Promise<void>;
  exportDemo(accessToken: string): Promise<void>;
  /** M14: has this user proved they receive mail at the stored address? */
  emailVerificationStatus(accessToken: string): Promise<EmailVerificationStatus>;
  /** M14: mail another code to the address already on file for this user. */
  resendEmailVerification(accessToken: string): Promise<ResendOutcome>;
  /**
   * M14: redeem a mailed code. Throws INVALID_VERIFICATION_CODE for every
   * refusal identity makes — it answers one uniform `invalid_code` and the edge
   * carries that through — or VERIFICATION_UNAVAILABLE when the code was fine
   * and the platform could not finish.
   *
   * NEVER INVALID_CREDENTIALS. That token means "email and password" on the
   * login surface, and the M12 review's finding was exactly that collision. An
   * earlier draft of THIS LINE said it throws INVALID_CREDENTIALS, which would
   * have led a second implementation straight back into that defect — the
   * interface is the contract, so the contract has to say the right thing.
   */
  verifyEmail(accessToken: string, code: string): Promise<void>;
  /**
   * Revokes exactly the presented session. Resolves false when identity
   * refuses the ACCESS token (401) — which means only that the 15-minute
   * token expired, NOT that the session is gone; use `logoutByRefresh`.
   */
  logout(accessToken: string): Promise<boolean>;
  /** Revokes the session behind a refresh token (the 30-day credential). */
  logoutByRefresh(refreshToken: string): Promise<void>;
  /**
   * M15: mint a single-use code for the isolated vault origin. Step-up gated at
   * identity, so a stale session raises STEPUP_REQUIRED and the UI prompts.
   */
  mintVaultHandoff(accessToken: string): Promise<{ code: string; expiresAt: string }>;
  /**
   * M21 PR3a. A SEPARATE METHOD FOR A SEPARATE ROUTE, not a parameter on the
   * one above: nothing on the wire names an audience, so there is no field a
   * caller could set and no argument a later edit could widen.
   */
  mintOperatorHandoff(accessToken: string): Promise<{ code: string; expiresAt: string }>;
  /** The caller's live sessions — the paired-devices surface (M16). */
  sessions(accessToken: string): Promise<LiveSession[]>;
  /** Revoke ONE of the caller's own sessions. 404 ⇒ unknown OR not theirs. */
  revokeSession(accessToken: string, sessionId: string): Promise<void>;
  /** Mint a browser-extension pairing code. Step-up gated at identity. */
  startExtensionPairing(accessToken: string): Promise<{ code: string; expiresAt: string }>;
  /**
   * M17 PR5 — the passkey ceremonies. The options/verify payloads are OPAQUE
   * to this edge by design: attestation semantics belong to identity's
   * library, identity re-validates shape and substance before any effect, and
   * a second validator here would be the PR3 wire-drift class (two shapes free
   * to disagree, with the disagreement invisible until production). The edge
   * forwards, maps error tokens, and adds nothing.
   */
  webauthnRegisterOptions(accessToken: string): Promise<unknown>;
  webauthnRegister(accessToken: string, response: Record<string, unknown>): Promise<void>;
  webauthnStepUpOptions(accessToken: string): Promise<unknown>;
  webauthnStepUp(
    accessToken: string,
    response: Record<string, unknown>,
  ): Promise<{ stepupExpiresAt: string }>;
  /** The passkey list — labels and timestamps, never key material. */
  passkeys(accessToken: string): Promise<Passkey[]>;
  /** Revoke one passkey. Step-up gated at identity; 404 ⇒ unknown OR not theirs. */
  revokePasskey(accessToken: string, id: string): Promise<void>;
  /** Label one passkey. 404 ⇒ unknown OR not theirs. */
  renamePasskey(accessToken: string, id: string, nickname: string): Promise<void>;
  /**
   * M20 PR1: change the ACCOUNT password. The first product consumer of any of
   * M17's six recovery routes.
   *
   * BOTH halves are required and each covers what the other cannot: the current
   * password is the one thing a stolen SESSION does not carry, and the fresh
   * factor is the one thing a stolen PASSWORD does not carry.
   *
   * STEP-UP IS CONDITIONAL, and a caller must be built for both paths.
   * Identity gates on `SecondFactorGate`, which refuses only when the account
   * already holds a verified TOTP or passkey — an account with no factor has
   * nothing to prove and is let through, deliberately, or its password would be
   * unchangeable forever. So STEPUP_REQUIRED is a possible answer, not a
   * guaranteed first one.
   *
   * Throws INVALID_CREDENTIALS when the CURRENT password is wrong — which on a
   * form with no email field does not mean what `errorCopy` says it means; the
   * web surface reads it through `passwordChangeMessageFor`.
   * Throws TOO_MANY_ATTEMPTS (429) once M17's per-session or per-account bound
   * is spent.
   *
   * On success identity revokes every OTHER live session and leaves the
   * caller's own alive.
   */
  changePassword(accessToken: string, currentPassword: string, newPassword: string): Promise<void>;

  /**
   * Stage a change of the account's sign-in address (M20 PR2, M17 PR4's
   * ceremony). VERIFY-THEN-SWITCH: nothing on file moves until a code mailed to
   * the NEW address comes back, because login resolves users by `email_bidx` and
   * an unproven address would lock its owner out of login itself.
   *
   * THE 202 IS NOT A DELIVERY RECEIPT and callers must not render it as one.
   * Identity answers before the send: the availability lookup, the encrypt, the
   * stage and the mail all run detached, so an address that already belongs to
   * somebody else returns exactly this answer and simply never mails. That
   * uniformity is the control — the caller learns nothing about who else holds
   * an address — and it means the only honest copy is conditional.
   *
   * Throws STEPUP_REQUIRED (conditional, on `SecondFactorGate` — the bootstrap
   * account with no factor is let through), INVALID_CREDENTIALS for a wrong
   * CURRENT password, CODE_REQUESTED_RECENTLY for either re-issue bound, and
   * INVALID_REQUEST for a malformed address OR one that is already this
   * account's — identity answers `invalid_request` for both and the surface
   * cannot tell them apart.
   */
  requestEmailChange(accessToken: string, currentPassword: string, newEmail: string): Promise<void>;

  /**
   * Finish the change by presenting the code mailed to the new address.
   *
   * Throws INVALID_VERIFICATION_CODE for EIGHT distinct server-side causes —
   * unknown, expired, spent, attempts exhausted, a lost race, a rotated key, and
   * the candidate address having been registered by somebody else mid-window.
   * Identity answers one `invalid_code` for all of them and THAT UNIFORMITY IS
   * THE CONTROL, so the edge carries it through rather than re-deriving
   * distinctions; the copy enumerates possibilities instead.
   *
   * On success the new address is live AND already verified (the code proved
   * it), outstanding reset and address-verification codes are swept in the same
   * transaction, and every OTHER session is revoked.
   */
  completeEmailChange(accessToken: string, code: string): Promise<void>;

  /**
   * Abandon a staged change. IDEMPOTENT and ungated beyond the session: it
   * answers 204 whether or not anything was pending, and it is deliberately not
   * step-up gated — the M6 rule that the protective action must never be harder
   * than the permissive one.
   */
  cancelEmailChange(accessToken: string): Promise<void>;

  /**
   * "Mail me a reset code" (M17 PR3's route; M20 PR3 is its first consumer).
   * UNAUTHENTICATED — the caller has forgotten the credential that would
   * authenticate them, so there is no token parameter at all.
   *
   * RESOLVING SAYS ALMOST NOTHING, and callers must render it that way:
   * identity answers 202 for EVERY well-formed input, and an unknown address,
   * the 30-minute re-issue floor and the per-destination bound are all
   * deliberately silent — a hit on this route tells an attacker where to point
   * a mailbox compromise, so an address with an account must be
   * indistinguishable from a stranger's. The only honest success copy is
   * conditional on all three.
   */
  requestPasswordReset(email: string): Promise<void>;

  /**
   * Redeem the mailed code and set a new password. UNAUTHENTICATED: the code
   * is the authority, and there is no field in the request that could name an
   * account.
   *
   * Throws INVALID_VERIFICATION_CODE for every dead-code reason (one
   * `invalid_code` covers unknown, expired, spent, revoked — the uniformity is
   * the control) and INVALID_REQUEST for a malformed body, which in practice
   * means a new password under identity's minimum.
   *
   * ON SUCCESS THE CALLER IS SIGNED IN NOWHERE: identity revokes EVERY session
   * and mints nothing — no tokens in the response, so the resolver sets no
   * cookie and the user signs in with what they just chose. The absence is a
   * control (the M15 PR4 lesson), pinned on identity's side by
   * `mint-paths.spec.ts`.
   */
  completePasswordReset(code: string, newPassword: string): Promise<void>;
}

export interface Passkey {
  readonly id: string;
  readonly nickname: string | null;
  readonly isHardwareKey: boolean;
  readonly createdAt: string;
  readonly lastUsedAt: string | null;
}

export interface LiveSession {
  readonly sessionId: string;
  /*
   * A STRING, not `SessionAudience`, and the widening is deliberate: this row
   * comes from a peer that may be deployed ahead of this build, and the type
   * has to be able to hold what identity actually sent. The resolver names an
   * unrecognised value `UNKNOWN` on the wire. `SessionContext.audience` — the
   * one an authorization decision is ever made from — stays the closed union.
   */
  readonly audience: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly current: boolean;
}

export type BffErrorCode =
  | 'UNAUTHENTICATED'
  | 'STEPUP_REQUIRED'
  | 'INVALID_REQUEST'
  | 'INVALID_CREDENTIALS'
  /**
   * The assistant's UNIFORM not-found (M11). It covers "no such conversation"
   * and "someone else's conversation" identically, on purpose: a code that told
   * them apart would turn an id into an oracle for whether a given user has the
   * assistant and how much they use it. Named rather than folded into a generic
   * failure because a client still has to render "that conversation is gone".
   */
  | 'NOT_FOUND'
  /**
   * The `assistant.enabled` master switch is off (M11). Distinct from every
   * other refusal because it is the one the USER can fix, and telling them so
   * is the difference between a feature that looks broken and one that looks
   * gated.
   */
  | 'ASSISTANT_DISABLED'
  /**
   * No reviewed template exists for that instrument in that state (M12). A 404
   * like NOT_FOUND, and deliberately not folded into it: one is a fact about
   * the platform's catalog, the other a fact about the caller's own documents,
   * and only one of them is worth telling someone to pick a different state
   * over.
   */
  | 'TEMPLATE_NOT_FOUND'
  /**
   * The version's content DEK was crypto-shredded, so the ciphertext can never
   * be opened again (M12). Its own code because the answer is PERMANENT —
   * rendering it as a transient failure would have someone retry forever
   * against a key destroyed on purpose.
   */
  | 'CONTENT_ERASED'
  /**
   * Someone else advanced the RESOURCE between read and write — a document
   * (M12) or an asset (M19, whose six ledger commands all carry
   * `expectedVersion`). Distinct from DOCUMENT_NOT_EDITABLE because the remedy
   * is different: reload, then try again.
   *
   * The wording below is deliberately resource-NEUTRAL. It said "this document
   * changed" until the M19 PR4 review, which meant an asset conflict reached
   * the wire describing a document the mutation never touched — `maskedErrors`
   * passes GraphQLErrors through unchanged, so this string IS what a non-web
   * client reads. apps/web keys on `extensions.code` and has its own copy, so
   * no browser ever showed it; that is what let it drift.
   */
  | 'VERSION_CONFLICT'
  /**
   * Live beneficiary shares for one designation class would exceed 100%
   * (M19 PR3 — the ledger's share-sum invariant, app check + DB trigger).
   * Its own code because it is the one refusal the owner fixes by choosing a
   * DIFFERENT NUMBER; folded into INVALID_REQUEST it would read as a form
   * mistake rather than as arithmetic over designations they cannot see from
   * the form.
   */
  | 'SHARE_SUM_EXCEEDED'
  /**
   * Regeneration refused because signing has started (M12). A signed or
   * executed instrument's content is a legal record; the way forward is to
   * revoke or supersede it, not to rewrite it underneath the signatures.
   */
  | 'DOCUMENT_NOT_EDITABLE'
  /**
   * The document is preserved as part of an estate matter (M12 PR2). The one
   * refusal on this surface the owner cannot resolve by authenticating harder,
   * so it must not look like one that step-up would fix.
   */
  | 'LEGAL_HOLD'
  /**
   * The attested status is not the next rung of THIS document's ladder (M12
   * PR2) — a skipped witness or notary step, or a move from a terminal status.
   */
  | 'INVALID_TRANSITION'
  /**
   * A real scanner found a signature match (M12 PR2). Deliberately its own
   * code: it must never be softened into "unsupported file", because the user
   * is holding a file somebody sent them and needs to know why.
   */
  | 'MALWARE_DETECTED'
  /**
   * The bytes are not a format this platform accepts, or the declared type did
   * not match the magic bytes (M12 PR2). Nothing was stored.
   */
  | 'UNSUPPORTED_CONTENT'
  /**
   * The malware scanner could not be reached (M12 PR2). FAIL CLOSED: nothing
   * was stored, and the honest answer is "we could not check it".
   */
  | 'SCAN_UNAVAILABLE'
  /**
   * A contact still named by a live role assignment. Actionable and deliberately
   * distinct: deleting such a contact used to silently retire its fiduciary
   * designations (M13 PR1), so the refusal has to say what to do about it —
   * revoke the roles naming this person first.
   */
  | 'CONTACT_IN_USE'
  /** The contact already has a platform user linked to it (M13). */
  | 'ALREADY_LINKED'
  /**
   * A link code was refused. ONE code for every reason — unknown, expired,
   * spent, revoked, self-directed — because distinguishing them tells whoever is
   * holding a guess that it named something real (M13).
   */
  | 'INVALID_LINK_CODE'
  /**
   * Redemption refused because the owner could not be told about it. Not an
   * outage to work around: the notification IS the control that makes a claimed
   * link visible to the person whose estate it opens (M13).
   */
  | 'NOTIFICATIONS_UNAVAILABLE'
  /** That exact designation is already live on that contact (M13, migration 004). */
  | 'ROLE_ALREADY_GRANTED'
  /** That exact permission is already live on that role (M13, migration 005). */
  | 'PERMISSION_ALREADY_GRANTED'
  /**
   * A permission over something the platform does not yet enforce. Only
   * `contact`/`read` is read by anything; every other pair used to be stored
   * and listed back as an allowance while conferring nothing, so profile now
   * refuses it. Deliberately not INVALID_REQUEST: "we have not built this yet"
   * and "your request was malformed" call for different words.
   */
  | 'GRANT_NOT_ENFORCED'
  /**
   * M14's address-verification code was refused. The `INVALID_LINK_CODE`
   * shape, for the same reason: identity answers ONE `invalid_code` for
   * unknown, expired, spent, revoked, attempt-exhausted and
   * belonging-to-someone-else, and that uniformity IS the control — the edge
   * carries it through rather than re-deriving distinctions from status codes.
   *
   * Kept out of `INVALID_CREDENTIALS` deliberately. That token already means
   * "email and password" on the login surface, and the M12 review's finding
   * was precisely that one code changing meaning with the surface produces
   * copy telling a user to check a password on a form that has none.
   */
  | 'INVALID_VERIFICATION_CODE'
  /**
   * The platform could not complete a verification it otherwise accepted —
   * the delivery store has no live row to vouch for (never fed, soft-deleted,
   * crypto-shredded). Distinct from `INVALID_VERIFICATION_CODE` because the
   * code was fine and there is nothing for the user to re-check, and distinct
   * from `NOTIFICATIONS_UNAVAILABLE` because nothing is down.
   */
  | 'VERIFICATION_UNAVAILABLE'
  /**
   * M15. The handoff could not be minted — identity answered something this
   * client could not read. Its own code rather than a generic failure because
   * the remedy is "try again in a moment", and because the vault is the one
   * surface where a user who is bounced needs to know it was the platform and
   * not their credentials.
   */
  | 'VAULT_UNAVAILABLE'
  /**
   * M16. The extension pairing code could not be minted — identity answered
   * something this client could not read.
   *
   * ITS OWN CODE, and the reason is the M12 finding rather than a taste for
   * granularity. This path first reused `VAULT_UNAVAILABLE`, whose copy reads
   * "we couldn't open the vault just now — nothing about your vault has
   * changed", on a screen that is about connecting a browser extension and
   * where nothing was opening a vault. One code changing meaning with the
   * surface is exactly what produced copy about a password on a form that has
   * none; and the remedy differs too, because there is no vault state to
   * reassure anyone about here, only a code that did not arrive.
   */
  | 'PAIRING_UNAVAILABLE'
  /**
   * M21 PR3a. The operator handoff code could not be minted — identity
   * answered something this client could not read.
   *
   * ITS OWN CODE for the reason `PAIRING_UNAVAILABLE` is: `VAULT_UNAVAILABLE`'s
   * copy is about a vault, and nothing on the operator surface is opening one.
   * One code changing meaning with the surface is the M12 finding, and this
   * repo has now met it three times — so a third surface gets a third sentence
   * rather than borrowing one that is nearly right.
   */
  | 'OPERATOR_UNAVAILABLE'
  /**
   * M17 PR5. A passkey ceremony was refused — identity answers one generic
   * `webauthn_failed` for every reason (bad attestation, consumed challenge,
   * clone detection, an authenticator already bound to another account),
   * deliberately, and this edge preserves the uniformity rather than
   * dissecting it. ITS OWN CODE because the remedy ("try the passkey ceremony
   * again") shares nothing with INVALID_CREDENTIALS' password-shaped copy or
   * INVALID_REQUEST's generic one — the M12 rule, applied before the collision
   * rather than after it.
   */
  | 'WEBAUTHN_FAILED'
  /**
   * M19 PR4 review. A rate bound refused the request — identity's step-up cap
   * (M17 PR6's two-scope bound: a stolen credential exhausts its OWN budget
   * under an account ceiling) answers 429 `too_many_attempts`.
   *
   * ITS OWN CODE because without one it fell through to the generic branch and
   * a control firing exactly as designed reached the browser as "something went
   * wrong on our side" — the M9 rule inverted, and the same reason the 404
   * branch beside it is mapped rather than left generic. The remedy is also the
   * one remedy no other code on this list implies: WAIT. Every other refusal
   * here is fixed by doing something differently now; this one is fixed by
   * doing the same thing later, so copy that says "try again" is actively
   * wrong.
   *
   * Deliberately NOT folded into INVALID_CREDENTIALS, which is what the step-up
   * surfaces render for a rejected code: the whole point of the cap is that the
   * next code will not be accepted either, however correct it is.
   */
  | 'TOO_MANY_ATTEMPTS'
  /**
   * A change was requested so recently that identity refuses to start another
   * (M20 PR2). Identity answers one `too_soon` for TWO conditions — the
   * per-account re-issue floor and the per-destination address bound — so one
   * sentence must cover both.
   *
   * ITS OWN CODE rather than `TOO_MANY_ATTEMPTS`, which is the closest existing
   * fit and is wrong in the direction that matters: its copy ends "Nothing is
   * wrong with your code or your account", which reads as a platform hiccup,
   * whereas this refusal is a considered answer about a request the caller
   * themselves made minutes ago and whose likely remedy is to go and read the
   * mail they already asked for.
   *
   * NAMED FOR THE REQUEST, NOT FOR A SEND, and the distinction is load-bearing
   * rather than pedantic: the address bound fires on volume aimed at a
   * DESTINATION, and a destination that already belongs to somebody else stages
   * nothing and mails nothing (the silent-availability control). So a caller
   * can reach this refusal having never been sent anything, and a code called
   * `CODE_ALREADY_SENT` — with copy telling them to use the one they were sent
   * — would send them looking for a mail that will never arrive. The whole
   * route is arranged so that no answer implies delivery; its refusals must not
   * either.
   */
  | 'CODE_REQUESTED_RECENTLY'
  /**
   * The waiting period cannot change while a settlement case about this owner
   * is open (M22 PR3). A CONTROL FIRING, not bad input: the parameters of a
   * pending case are frozen so a step-up-fresh stolen session cannot shorten
   * the very window designed to catch it. Its own code because its own remedy
   * — resolve or void the case, then change the setting.
   */
  | 'CASE_OPEN'
  /**
   * The case has passed verification, so the subject's own kill switch no
   * longer applies and rescue is an operator ceremony (M22 PR3).
   *
   * DELIBERATELY NOT `INVALID_TRANSITION`, which the service also spells
   * `invalid_transition` on the wire. That code's copy names a DOCUMENT and
   * its remedy is a different next step; this one is about a death case and
   * the remedy is "contact us". Same token downstream, different sentence to
   * the person reading it — which is exactly the split this repo's rule asks
   * for.
   */
  | 'CASE_NOT_VOIDABLE'
  | 'CASE_ALREADY_REPORTED'
  | 'EVIDENCE_WINDOW_CLOSED'
  /**
   * A settlement transition rolled back because identity or documents could
   * not be reached (M22 PR3). NOTHING HAPPENED and the remedy is to try again.
   *
   * This one earns its place on the kill switch specifically: an owner told
   * "we could not do that right now" tries again, an owner told "that is not
   * allowed" gives up, and a fraudulent case about them stays alive on the
   * difference. Which downstream was down is collapsed on purpose.
   */
  | 'SETTLEMENT_UNAVAILABLE';

const ERROR_MESSAGES: Record<BffErrorCode, string> = {
  UNAUTHENTICATED: 'Not authenticated',
  STEPUP_REQUIRED: 'Step-up verification required',
  INVALID_REQUEST: 'Invalid request',
  INVALID_CREDENTIALS: 'Invalid credentials',
  NOT_FOUND: 'Not found',
  ASSISTANT_DISABLED: 'The assistant is switched off',
  TEMPLATE_NOT_FOUND: 'No template available',
  CONTENT_ERASED: 'This content has been erased',
  VERSION_CONFLICT: 'This changed since it was loaded',
  SHARE_SUM_EXCEEDED: 'Those shares would add past 100%',
  DOCUMENT_NOT_EDITABLE: 'This document can no longer be regenerated',
  LEGAL_HOLD: 'This document is under legal hold',
  INVALID_TRANSITION: 'That is not the next step for this document',
  MALWARE_DETECTED: 'That file was refused by the malware scanner',
  UNSUPPORTED_CONTENT: 'That file type is not accepted',
  SCAN_UNAVAILABLE: 'That file could not be checked for malware',
  CONTACT_IN_USE: 'This person still holds a role in your estate',
  ALREADY_LINKED: 'This person already has an account linked',
  INVALID_LINK_CODE: 'That invitation code was not accepted',
  NOTIFICATIONS_UNAVAILABLE: 'We cannot notify the account owner right now',
  ROLE_ALREADY_GRANTED: 'That role is already recorded for this person',
  PERMISSION_ALREADY_GRANTED: 'That permission is already allowed for this role',
  GRANT_NOT_ENFORCED: 'This platform does not yet share that part of an estate',
  INVALID_VERIFICATION_CODE: 'That code was not accepted',
  VERIFICATION_UNAVAILABLE: 'We could not confirm that address right now',
  VAULT_UNAVAILABLE: 'We could not open the vault right now',
  PAIRING_UNAVAILABLE: 'We could not create a pairing code right now',
  OPERATOR_UNAVAILABLE: 'We could not open the operator console right now',
  WEBAUTHN_FAILED: 'The passkey ceremony was not accepted',
  TOO_MANY_ATTEMPTS: 'Too many attempts — wait a few minutes before trying again',
  CODE_REQUESTED_RECENTLY: 'A change was requested recently — wait before asking for another',
  CASE_OPEN: 'This cannot change while a case about you is open',
  CASE_NOT_VOIDABLE: 'This case has moved past the point where you can close it yourself',
  CASE_ALREADY_REPORTED: 'A case is already open on this estate',
  EVIDENCE_WINDOW_CLOSED: 'This case has moved past the point where more can be attached to it',
  SETTLEMENT_UNAVAILABLE: 'We could not complete that right now — nothing has changed',
};

/**
 * The machine-readable token from an error body, or '' when there is not one.
 * Shared so a mapper can look at the token WITHOUT consuming the response the
 * shared mapper will read again.
 */
async function readErrorToken(res: Response): Promise<string> {
  try {
    const parsed = ErrorBodySchema.safeParse(await res.json());
    return parsed.success ? parsed.data.error : '';
  } catch {
    return '';
  }
}

/** GraphQLError with a stable machine-readable code; safe to expose. */
export function bffError(code: BffErrorCode): GraphQLError {
  return new GraphQLError(ERROR_MESSAGES[code], { extensions: { code } });
}

const TokensSchema = z.object({
  accessToken: z.string().min(1),
  refreshToken: z.string().min(1),
  sessionId: z.string().min(1),
  userId: z.string().min(1),
});

const VerificationStatusSchema = z.object({
  status: z.enum(['verified', 'unverified', 'unavailable']),
});

const ResendSchema = z.object({
  outcome: z.enum(['sent', 'too_soon', 'already_verified', 'unavailable']),
});

const SessionSchema = z.object({
  userId: z.string().min(1),
  sessionId: z.string().min(1),
  mfaLevel: MfaLevelSchema,
  stepupExpiresAt: z.string().nullable(),
  // Tolerant of an identity that predates the field, for the same reason
  // auth-guard's verifier is: only identity mints a non-account audience, so an
  // identity old enough to omit it has none to describe. An UNRECOGNISED value
  // is a different matter and fails the parse.
  audience: SessionAudienceSchema.default(DEFAULT_SESSION_AUDIENCE),
});

const EnrollSchema = z.object({
  methodId: z.string().min(1),
  otpauthUri: z.string().min(1),
});

/**
 * A minted single-use code and when it dies — M15's vault handoff and M16's
 * extension pairing have the same wire shape.
 *
 * Shape-checked rather than trusted, like every other identity response here: a
 * malformed body must become a failure, never a form the browser submits with
 * `code=undefined` to the vault origin, and never a pairing code the user
 * copies as the literal string "undefined". Named for the shape rather than for
 * the first ceremony that used it, because the second one already exists — a
 * `VaultHandoffSchema` parsing extension pairings is how a reader concludes the
 * two ceremonies are the same thing.
 */
const MintedCodeSchema = z.object({
  code: z.string().min(1),
  expiresAt: z.string().min(1),
});

/*
 * THE ROW IS TOLERANT WHERE `SessionSchema` IS STRICT, and the asymmetry is the
 * point rather than an oversight.
 *
 * A `z.array` of strict objects fails WHOLESALE: one row carrying an audience
 * this build has not heard of discarded the entire response, `parseBody` threw,
 * and the paired-devices page rendered an error INSTEAD OF THE ROWS THE USER
 * CAME TO REVOKE. That is the page somebody opens when they believe a device is
 * compromised, and `lib/sessions.ts` already carries the fallback copy for
 * exactly this case — citing the rule that a service deployed ahead of the app
 * must not blank the page. The fallback was unreachable, because the edge
 * refused one layer up.
 *
 * So an unrecognised audience is carried as an opaque string and named
 * `UNKNOWN` on the wire, never coerced to `account`: mislabelling somebody's
 * unrecognised credential as "this browser" is worse than the blank page, since
 * it argues them out of revoking it. The one thing this must not do is drop the
 * row, which would hide it entirely.
 */
const LiveSessionsSchema = z.object({
  sessions: z.array(
    z.object({
      sessionId: z.string().min(1),
      audience: z.string().min(1),
      createdAt: z.string().min(1),
      expiresAt: z.string().min(1),
      current: z.boolean(),
    }),
  ),
});

/** M17 PR5. */
const PasskeysSchema = z.object({
  credentials: z.array(
    z.object({
      id: z.string().min(1),
      nickname: z.string().nullable(),
      isHardwareKey: z.boolean(),
      createdAt: z.string().min(1),
      lastUsedAt: z.string().nullable(),
    }),
  ),
});
const StepUpResultSchema = z.object({
  mfaLevel: z.string(),
  stepupExpiresAt: z.string().min(1),
});

const ErrorBodySchema = z.object({ error: z.string() });

export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

interface RequestOptions {
  method: 'GET' | 'POST' | 'DELETE' | 'PATCH';
  path: string;
  accessToken?: string;
  /** Widened from Record<string, string> for M17 PR5: a WebAuthn attestation
   * is nested JSON. The transport has always JSON.stringify'd whatever it was
   * handed; only the TYPE was flat. */
  body?: Record<string, unknown>;
}

export class FetchIdentityClient implements IdentityClient {
  private readonly fetchFn: FetchFn;

  constructor(
    private readonly baseUrl: string,
    fetchFn?: FetchFn,
  ) {
    this.fetchFn = fetchFn ?? ((input, init): Promise<Response> => globalThis.fetch(input, init));
  }

  async register(email: string, password: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/register',
      body: { email, password },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async login(email: string, password: string): Promise<IssuedTokens> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/login',
      body: { email, password },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, TokensSchema);
  }

  async refresh(refreshToken: string): Promise<IssuedTokens> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/refresh',
      body: { refreshToken },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, TokensSchema);
  }

  async session(accessToken: string): Promise<IdentitySession | null> {
    const res = await this.request({ method: 'GET', path: '/v1/auth/session', accessToken });
    if (res.status === 401) {
      // Invalid/expired token ⇒ "not authenticated", not an error.
      return null;
    }
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, SessionSchema);
  }

  async totpEnroll(accessToken: string): Promise<TotpEnrollment> {
    const res = await this.request({ method: 'POST', path: '/v1/auth/totp/enroll', accessToken });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    const { otpauthUri } = await this.parseBody(res, EnrollSchema);
    return { otpauthUri };
  }

  async totpVerify(accessToken: string, code: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/totp/verify',
      accessToken,
      body: { code },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async stepUp(accessToken: string, code: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/stepup',
      accessToken,
      body: { code },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async emailVerificationStatus(accessToken: string): Promise<EmailVerificationStatus> {
    const res = await this.request({
      method: 'GET',
      path: '/v1/auth/email/verification',
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return (await this.parseBody(res, VerificationStatusSchema)).status;
  }

  async resendEmailVerification(accessToken: string): Promise<ResendOutcome> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/email/verification/resend',
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return (await this.parseBody(res, ResendSchema)).outcome;
  }

  async verifyEmail(accessToken: string, code: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/email/verification/verify',
      accessToken,
      body: { code },
    });
    if (!res.ok) {
      // Every refusal identity makes here is the SAME `invalid_code`, and it
      // has to stay that way through the edge: unknown, expired, spent,
      // revoked, attempt-exhausted and belonging-to-someone-else must remain
      // indistinguishable, or the edge re-creates the oracle the uniform
      // answer removes from the service.
      throw await this.mapVerifyError(res);
    }
  }

  async exportDemo(accessToken: string): Promise<void> {
    const res = await this.request({ method: 'POST', path: '/v1/auth/export-demo', accessToken });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  /**
   * Mint a single-use handoff code for the isolated vault origin (M15).
   *
   * Step-up gated at identity, so a stale session gets `stepup_required` and
   * the UI prompts — the same shape every other elevated action here uses. The
   * code is returned in the BODY and must never reach a URL: it is put in a
   * hidden form field and submitted by top-level POST.
   */
  async mintVaultHandoff(accessToken: string): Promise<{ code: string; expiresAt: string }> {
    const res = await this.request({ method: 'POST', path: '/v1/auth/handoff', accessToken });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    const parsed = MintedCodeSchema.safeParse(await res.json());
    if (!parsed.success) {
      throw bffError('VAULT_UNAVAILABLE');
    }
    return parsed.data;
  }

  /**
   * Mint a single-use handoff code for the ISOLATED OPERATOR ORIGIN (M21 PR3a).
   *
   * A SEPARATE ROUTE from the vault's, not a body field naming an audience, and
   * that is the whole design: the route is the selector, so no client can ask
   * for an audience and identity's own `HANDOFF_AUDIENCES` is the only place
   * the vocabulary exists. Step-up gated and account-audience only at identity,
   * so a vault or operator session cannot mint another credential.
   *
   * MINTING IS ROLE-BLIND, deliberately. An `operator` audience is a
   * RESTRICTION on where a credential may be spent, never a claim about who is
   * holding it — whether the caller may act on a settlement case is decided by
   * `settlement_operators`, inside the transaction that would act. The BFF
   * holds no settlement credential and could not ask even if it should.
   */
  async mintOperatorHandoff(accessToken: string): Promise<{ code: string; expiresAt: string }> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/handoff/operator',
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    const parsed = MintedCodeSchema.safeParse(await res.json());
    if (!parsed.success) {
      throw bffError('OPERATOR_UNAVAILABLE');
    }
    return parsed.data;
  }

  async sessions(accessToken: string): Promise<LiveSession[]> {
    const res = await this.request({ method: 'GET', path: '/v1/auth/sessions', accessToken });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return (await this.parseBody(res, LiveSessionsSchema)).sessions;
  }

  /**
   * Revoke one session. Identity answers a UNIFORM 404 for "no such session"
   * and "not yours" alike — the owner predicate is in its UPDATE — so this
   * surfaces NOT_FOUND for both and the edge adds no distinction of its own.
   */
  async revokeSession(accessToken: string, sessionId: string): Promise<void> {
    const res = await this.request({
      method: 'DELETE',
      path: `/v1/auth/sessions/${encodeURIComponent(sessionId)}`,
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async startExtensionPairing(accessToken: string): Promise<{ code: string; expiresAt: string }> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/extension/pairing',
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    // The shape guard VaultLaunch's defect taught: a pairing code rendered as
    // `undefined` is worse than an error, because the user copies it.
    const parsed = MintedCodeSchema.safeParse(await res.json());
    if (!parsed.success) {
      throw bffError('PAIRING_UNAVAILABLE');
    }
    return parsed.data;
  }

  async webauthnRegisterOptions(accessToken: string): Promise<unknown> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/webauthn/register/options',
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return res.json();
  }

  async webauthnRegister(accessToken: string, response: Record<string, unknown>): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/webauthn/register/verify',
      accessToken,
      body: response,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async webauthnStepUpOptions(accessToken: string): Promise<unknown> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/webauthn/authenticate/options',
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return res.json();
  }

  async webauthnStepUp(
    accessToken: string,
    response: Record<string, unknown>,
  ): Promise<{ stepupExpiresAt: string }> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/webauthn/authenticate/verify',
      accessToken,
      body: response,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    const parsed = StepUpResultSchema.safeParse(await res.json());
    if (!parsed.success) {
      // A missing field is NO DATA, never data (the M15 VaultLaunch rule).
      throw bffError('WEBAUTHN_FAILED');
    }
    return { stepupExpiresAt: parsed.data.stepupExpiresAt };
  }

  async passkeys(accessToken: string): Promise<Passkey[]> {
    const res = await this.request({
      method: 'GET',
      path: '/v1/auth/webauthn/credentials',
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return (await this.parseBody(res, PasskeysSchema)).credentials;
  }

  async revokePasskey(accessToken: string, id: string): Promise<void> {
    const res = await this.request({
      method: 'DELETE',
      path: `/v1/auth/webauthn/credentials/${encodeURIComponent(id)}`,
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async renamePasskey(accessToken: string, id: string, nickname: string): Promise<void> {
    const res = await this.request({
      method: 'PATCH',
      path: `/v1/auth/webauthn/credentials/${encodeURIComponent(id)}`,
      accessToken,
      body: { nickname },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async changePassword(
    accessToken: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/password',
      accessToken,
      body: { currentPassword, newPassword },
    });
    if (!res.ok) {
      // The SHARED mapper, deliberately — unlike `verifyEmail`, this route has
      // no uniform-refusal property to preserve. Its tokens are already covered:
      // 401 `invalid_credentials` ⇒ INVALID_CREDENTIALS, 403 `stepup_required`
      // ⇒ STEPUP_REQUIRED, 429 ⇒ TOO_MANY_ATTEMPTS (status-keyed, so M17's
      // bound surfaces as a refusal rather than as an outage), 400 ⇒
      // INVALID_REQUEST. No new `BffErrorCode` is needed.
      throw await this.mapError(res);
    }
    // 204 No Content. Deliberately NOT parsed: `parseBody` would throw
    // 'identity response was not JSON' on an empty body, turning every
    // SUCCESSFUL change into an error.
  }

  async requestEmailChange(
    accessToken: string,
    currentPassword: string,
    newEmail: string,
  ): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/email/change/request',
      accessToken,
      body: { currentPassword, newEmail },
    });
    if (!res.ok) {
      throw await this.mapChangeRequestError(res);
    }
    // 202 Accepted, body `{status:'ok'}` — deliberately not read. It reports
    // that the request was TAKEN, never that a mail was sent (the send is
    // detached), so there is nothing in it a caller may act on.
  }

  async completeEmailChange(accessToken: string, code: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/email/change',
      accessToken,
      // Passed through UNCHANGED. Identity measures and hashes the CANONICAL
      // fold, so folding here would be a second copy of a matching rule, free
      // to disagree with the one that decides (the `verifyEmail` precedent).
      body: { code },
    });
    if (!res.ok) {
      throw await this.mapCodeRedemptionError(res);
    }
    // 204 No Content — not parsed, for `changePassword`'s reason.
  }

  async requestPasswordReset(email: string): Promise<void> {
    // NO BEARER, by construction: the caller has forgotten the credential that
    // would authenticate them, and this method's signature has no token
    // parameter to leak one through.
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/password/reset/request',
      body: { email },
    });
    if (!res.ok) {
      // The SHARED mapper is correct on this route, unlike the email change's
      // request leg, and the difference is worth stating: identity answers 202
      // for EVERY well-formed input — an unknown address, the re-issue floor
      // and the destination bound are all deliberately silent — so the only
      // 400 this route can produce is a malformed body, which is exactly what
      // the status-keyed INVALID_REQUEST branch means.
      throw await this.mapError(res);
    }
    // 202 Accepted, body `{status:'ok'}` — deliberately not read. It reports
    // that the request was TAKEN, never that a mail was sent, refused by the
    // floor, or had nowhere to go. The caller is never told which, and that is
    // the route's own design (the account-existence timing control): there is
    // no field here a caller could mistake for a delivery receipt.
  }

  async completePasswordReset(code: string, newPassword: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/password/reset',
      // The code passes through UNCHANGED (the canonical fold lives in
      // identity), and the new password is not re-validated (identity's schema
      // is the gate — the M12 upload-client rule, as on `changePassword`).
      body: { code, newPassword },
    });
    if (!res.ok) {
      throw await this.mapCodeRedemptionError(res);
    }
    // 204 No Content — not parsed, for `changePassword`'s reason. IDENTITY
    // MINTS NOTHING HERE: no tokens in the response, no session to attach, so
    // completing a reset signs the caller in nowhere and the resolver sets no
    // cookie. That absence is a control (the M15 PR4 lesson — an
    // unauthenticated redeem route that granted authority let a stolen code
    // reach a Zone A crypto-shred), and identity's own `mint-paths.spec.ts`
    // pins it from the other side.
  }

  async cancelEmailChange(accessToken: string): Promise<void> {
    const res = await this.request({
      method: 'DELETE',
      path: '/v1/auth/email/change',
      accessToken,
    });
    if (!res.ok) {
      // The shared mapper suffices: this route has no domain refusal at all.
      // Its only non-204 is the guard's 401, so there is no token to interpret.
      throw await this.mapError(res);
    }
  }

  /**
   * THE SHARED MAPPER IS WRONG FOR THIS ROUTE, which is the whole reason this
   * exists. `mapError` is STATUS-keyed for 400 and turns every one of them into
   * INVALID_REQUEST — but identity answers **400** (not 401) for a rejected
   * CURRENT password here, so without this a wrong password would reach the
   * browser as "something about that request wasn't right", which names the
   * wrong field and implies the wrong remedy.
   */
  private async mapChangeRequestError(res: Response): Promise<Error> {
    if (res.status === 400) {
      const token = await readErrorToken(res.clone());
      if (token === 'invalid_credentials') {
        return bffError('INVALID_CREDENTIALS');
      }
      if (token === 'too_soon') {
        return bffError('CODE_REQUESTED_RECENTLY');
      }
      // `invalid_request` covers BOTH a malformed address and one that is
      // already this account's own — identity does not distinguish them, so
      // neither can this.
      return bffError('INVALID_REQUEST');
    }
    // Everything else falls through to the shared mapper, and one of those
    // fall-throughs became REACHABLE in M20 PR5: this route now carries the
    // account-password guessing bound it shipped without, so it can answer 429.
    // The shared 429 branch is status-keyed, so the refusal already surfaces as
    // TOO_MANY_ATTEMPTS rather than as an outage — no new branch, but the
    // reachability is worth stating, because "this cannot happen here" is how a
    // mapper falls behind the route it maps.
    return this.mapError(res);
  }

  /**
   * Same reason, redemption legs: identity answers **400** `invalid_code`, and
   * the shared mapper's 400 branch would flatten the one uniform refusal these
   * ceremonies have into INVALID_REQUEST. (Its 401 branch already maps
   * `invalid_code` to INVALID_CREDENTIALS, which is the login vocabulary and
   * equally wrong on a form whose only field is a mailed code — the M12
   * collision.)
   *
   * ONE mapper for BOTH mailed-code redemptions (the email change and the
   * password reset), because the two routes genuinely share the mapping —
   * one `invalid_code` for every dead reason, `invalid_request` for a
   * malformed body — and one behaviour with two spellings grows one bug per
   * copy (the M8 PR2 rule). What differs per surface is the COPY, which lives
   * in the app's per-surface message resolvers, not here.
   */
  private async mapCodeRedemptionError(res: Response): Promise<Error> {
    if (res.status === 400) {
      const token = await readErrorToken(res.clone());
      return token === 'invalid_code'
        ? bffError('INVALID_VERIFICATION_CODE')
        : bffError('INVALID_REQUEST');
    }
    return this.mapError(res);
  }

  async logout(accessToken: string): Promise<boolean> {
    const res = await this.request({ method: 'POST', path: '/v1/auth/logout', accessToken });
    if (res.status === 401) {
      // The ACCESS token is dead. That is NOT "logged out": the session and
      // its 30-day refresh token are still live, and treating this as success
      // is the M8-review defect — it revoked nothing while telling the user
      // they were signed out. The caller must fall back to the refresh path.
      return false;
    }
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return true;
  }

  async logoutByRefresh(refreshToken: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/logout/refresh',
      body: { refreshToken },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  private async request(options: RequestOptions): Promise<Response> {
    const headers: Record<string, string> = {};
    if (options.accessToken !== undefined) {
      headers.authorization = `Bearer ${options.accessToken}`;
    }
    const init: RequestInit = { method: options.method, headers };
    if (options.body !== undefined) {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(options.body);
    }
    try {
      return await this.fetchFn(`${this.baseUrl}${options.path}`, init);
    } catch {
      // Network/DNS failure. Plain Error ⇒ masked by yoga; cause never exposed.
      throw new Error('identity service unreachable');
    }
  }

  /**
   * Maps identity's generic error tokens to stable GraphQL error codes.
   * Anything unrecognized (5xx, malformed) becomes a plain Error so yoga's
   * error masking replaces it with a generic message.
   */
  /**
   * The verify route's two 400s mean different things to the person holding
   * the code, so they do not both collapse to INVALID_REQUEST. Everything
   * else falls through to the shared mapping.
   */
  private async mapVerifyError(res: Response): Promise<Error> {
    if (res.status === 400) {
      const token = await readErrorToken(res.clone());
      if (token === 'verification_unavailable') {
        return bffError('VERIFICATION_UNAVAILABLE');
      }
      return bffError('INVALID_VERIFICATION_CODE');
    }
    return this.mapError(res);
  }

  private async mapError(res: Response): Promise<Error> {
    let token = '';
    try {
      const body: unknown = await res.json();
      const parsed = ErrorBodySchema.safeParse(body);
      if (parsed.success) {
        token = parsed.data.error;
      }
    } catch {
      // Non-JSON body: fall through to status-based mapping.
    }
    // M17 PR5: identity's one generic ceremony refusal travels as 400
    // (registration) AND 401 (assertion). Token-first, or the 401 half would
    // collapse into UNAUTHENTICATED and the popup would forget a valid
    // session over a refused ceremony — the M16 PR2b lesson (an outage must
    // not wear the face of a revocation), one wire over.
    if (token === 'webauthn_failed') {
      return bffError('WEBAUTHN_FAILED');
    }
    if (res.status === 401) {
      return token === 'invalid_credentials' || token === 'invalid_code'
        ? bffError('INVALID_CREDENTIALS')
        : bffError('UNAUTHENTICATED');
    }
    if (res.status === 403 && token === 'stepup_required') {
      return bffError('STEPUP_REQUIRED');
    }
    // M19 PR4 review: identity's rate bounds (M16/M17) answer 429. Mapped for
    // the same reason as the 404 below — a control answering correctly must not
    // surface as an opaque server error — and status-keyed rather than
    // token-keyed on purpose: 429 means one thing on every route, and a future
    // bound arriving with a token this edge has not learned yet should still be
    // told apart from an outage.
    if (res.status === 429) {
      return bffError('TOO_MANY_ATTEMPTS');
    }
    if (res.status === 400) {
      return bffError('INVALID_REQUEST');
    }
    // M16: identity's first 404-returning route is session revocation, whose
    // answer is deliberately uniform across "unknown" and "not yours". Mapped
    // rather than left to the generic branch, which would surface a control
    // answering correctly as an opaque server error.
    if (res.status === 404) {
      return bffError('NOT_FOUND');
    }
    return new Error(`identity responded with status ${res.status}`);
  }

  private async parseBody<T extends z.ZodTypeAny>(res: Response, schema: T): Promise<z.infer<T>> {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new Error('identity response was not JSON');
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      // Field paths only — never response values.
      throw new Error('identity response failed validation');
    }
    return parsed.data as z.infer<T>;
  }
}
