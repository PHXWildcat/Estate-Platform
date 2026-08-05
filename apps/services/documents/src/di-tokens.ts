/** Nest injection tokens for non-class providers. */
export const CONFIG = Symbol('CONFIG');
export const PG_POOL_CONFIG = Symbol('PG_POOL_CONFIG');
export const AUDIT_PRODUCER = Symbol('AUDIT_PRODUCER');
export const FIELD_CRYPTO = Symbol('FIELD_CRYPTO');
export const DEK_REPOSITORY = Symbol('DEK_REPOSITORY');
export const POLICY_DECISION_POINT = Symbol('POLICY_DECISION_POINT');
export const OBJECT_STORE = Symbol('OBJECT_STORE');
export const MALWARE_SCANNER = Symbol('MALWARE_SCANNER');
export const OCR_ENGINE = Symbol('OCR_ENGINE');
export const CLOCK = Symbol('CLOCK');

/** Injectable clock so time-dependent logic is testable without real time. */
export type Clock = () => Date;

/**
 * GUC actor for writes the PLATFORM performs on a user's rows rather than the
 * user performing them — currently only the settlement-imposed legal hold
 * (M9 PR2), whose caller is a service credential and whose subject has no
 * session by construction. The `*_versions` triggers read `app.actor_id`, so
 * passing the owner here would record the decedent as the actor of a freeze
 * they could not have performed; in a docs/03 §5.1 fraud investigation the
 * version history is evidence, and it must not say the owner did this.
 * The matching audit event already gets it right (actorType 'service',
 * actorId null). Same sentinel as assets/notifications/settlement: set_config
 * needs a value, and uuid v4 never produces the zero UUID.
 */
export const SYSTEM_ACTOR_ID = '00000000-0000-0000-0000-000000000000';
