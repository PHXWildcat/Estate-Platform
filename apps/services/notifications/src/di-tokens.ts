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
 * the fact), while vault and profile ask at their two ARMING gates. Folding
 * the read into the send credential would hand settlement a capability it has
 * no use for and force a hedge into that edge's `grants` sentence, which
 * currently promises it exposes no delivery state.
 */
export const RECIPIENT_STATUS_CREDENTIAL = Symbol('RECIPIENT_STATUS_CREDENTIAL');

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
