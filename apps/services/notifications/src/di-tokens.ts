/** Nest injection tokens for non-class providers. */
export const CONFIG = Symbol('CONFIG');
export const PG_POOL_CONFIG = Symbol('PG_POOL_CONFIG');
export const AUDIT_PRODUCER = Symbol('AUDIT_PRODUCER');
export const EMAIL_SENDER = Symbol('EMAIL_SENDER');
export const FIELD_CRYPTO = Symbol('FIELD_CRYPTO');
export const DEK_REPOSITORY = Symbol('DEK_REPOSITORY');
export const CLOCK = Symbol('CLOCK');

/**
 * The credential for the RECIPIENT-UPSERT surface, distinct from the shared
 * `SERVICE_CREDENTIAL` that opens sending.
 *
 * This service is the one callee in the product whose internal routes fall
 * into two capability classes with different legitimate holders: anyone who
 * must notify a user may SEND (vault, settlement), but only identity — which
 * observes the user typing their address at registration and login — may say
 * WHERE a user's notifications go. The M9 security review found both behind
 * one secret, which handed vault and settlement the power to silently
 * redirect any owner's §5.1/§5.2 alerts to an attacker mailbox. A guard binds
 * exactly one token, so a second token is what makes the split real.
 */
export const RECIPIENTS_CREDENTIAL = Symbol('RECIPIENTS_CREDENTIAL');

/**
 * The credential for MAILING ONE ADDRESS-VERIFICATION CODE (M14). Identity
 * alone.
 *
 * Identity must be able to make the platform mail a code it minted, and must
 * NOT thereby gain the power to fire an estate notification — "a death report
 * was filed on your account" is not a message the session service should be
 * able to ring. So it is neither on `SERVICE_CREDENTIAL` (the estate send
 * surface, held by vault/settlement/profile) nor folded into
 * `RECIPIENTS_CREDENTIAL`, whose holder can REPOINT an address: this one can
 * only mail to whatever is already on file.
 */
export const VERIFICATION_CREDENTIAL = Symbol('VERIFICATION_CREDENTIAL');

/**
 * The credential for READING whether a user's address is verified (M14).
 *
 * A separate edge from sending because its holders differ: settlement sends
 * and never asks (its §5.1 gates PROCEED on an unverified recipient and record
 * the fact), while vault and profile ask at their two ARMING gates.
 *
 * It withholds the SILENT read, not the bit. The send response carries
 * `recipientVerified` as well — deliberately, so settlement can record the fact
 * without this credential — so what a non-holder gives up is the ability to ask
 * without mailing the subject and leaving a trail. The M14 review found this
 * comment claiming the send edge exposed no delivery state; it did from PR2
 * onward.
 */
export const RECIPIENT_STATUS_CREDENTIAL = Symbol('RECIPIENT_STATUS_CREDENTIAL');

/**
 * The credential for ACCOUNT-SECURITY notices (M17). Identity alone.
 *
 * The fifth edge on this callee, and the reasoning is the same shape as
 * VERIFY's with a different pair of neighbours. Not `SERVICE_CREDENTIAL`: that
 * is the estate surface held by vault, settlement and profile, and none of them
 * has any business telling a user their password changed — it is the single
 * most useful message an attacker could make the platform send, because it is
 * exactly a phishing pretext and a recipient acts on it. Not
 * `VERIFICATION_CREDENTIAL` either, despite the identical holder today: that
 * one mails a code the caller minted, and a future holder of a resend
 * capability (a support tool, a BFF-side resend) must not inherit the power to
 * announce credential changes. Splitting before the second holder exists is
 * what M14 did for VERIFY, and the alternative is re-litigating it later.
 */
export const SECURITY_CREDENTIAL = Symbol('SECURITY_CREDENTIAL');

/**
 * The credential for mailing a PASSWORD-RESET code (M17 PR3). Identity alone,
 * and the most powerful of this callee's four send surfaces.
 *
 * Not `VERIFICATION_CREDENTIAL`, despite the identical holder and a
 * near-identical payload: a verification code proves a mailbox and is redeemed
 * by somebody already signed in, while a reset code REPLACES the account
 * password and is redeemed with no session at all. Whoever can cause one to be
 * mailed and can read that mailbox owns the account. Not `SECURITY_CREDENTIAL`
 * either — that wire deliberately carries no variables, which is the property
 * that makes it safe.
 */
export const RECOVERY_CREDENTIAL = Symbol('RECOVERY_CREDENTIAL');

/**
 * The credential for the EMAIL-CHANGE CHALLENGE (M17 PR4). Identity alone,
 * and the one send surface on this callee whose payload NAMES A DESTINATION.
 *
 * Every other send resolves its recipient from the encrypted store by user id;
 * this ceremony is by definition a challenge to a mailbox the store does not
 * hold, so the destination can only come from the caller. Not
 * `VERIFICATION_CREDENTIAL`, whose recorded grant is "can only mail to
 * whatever is already on file" — folding an address field into it would hand
 * any future resend-tool holder the power to aim platform mail at arbitrary
 * addresses. Not `RECIPIENTS_CREDENTIAL` either: that one repoints and never
 * sends, and a repoint credential that gained a carrier send would be two
 * capability classes back under one secret, which is the M9 finding restated.
 */
export const EMAIL_CHANGE_CREDENTIAL = Symbol('EMAIL_CHANGE_CREDENTIAL');

/** Injectable clock so send records are testable without real time. */
export type Clock = () => Date;

/**
 * GUC actor for writes performed by this service rather than a user (recipient
 * upserts land on identity's word, sends on a peer service's). The audit
 * events carry actorType 'service' with a null actor; the version triggers get
 * this sentinel because set_config needs a value. No such user can exist:
 * uuid v4 never produces the zero UUID.
 */
export const SYSTEM_ACTOR_ID = '00000000-0000-0000-0000-000000000000';
