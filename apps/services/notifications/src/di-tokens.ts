/** Nest injection tokens for non-class providers. */
export const CONFIG = Symbol('CONFIG');
export const PG_POOL_CONFIG = Symbol('PG_POOL_CONFIG');
export const AUDIT_PRODUCER = Symbol('AUDIT_PRODUCER');
export const EMAIL_SENDER = Symbol('EMAIL_SENDER');
export const FIELD_CRYPTO = Symbol('FIELD_CRYPTO');
export const DEK_REPOSITORY = Symbol('DEK_REPOSITORY');
export const CLOCK = Symbol('CLOCK');

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
