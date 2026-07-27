/** Nest injection tokens for non-class providers. */
export const CONFIG = Symbol('CONFIG');
export const PG_POOL_CONFIG = Symbol('PG_POOL_CONFIG');
export const AUDIT_PRODUCER = Symbol('AUDIT_PRODUCER');
export const POLICY_DECISION_POINT = Symbol('POLICY_DECISION_POINT');
export const NOTIFIER = Symbol('NOTIFIER');
export const IDENTITY_LOCK = Symbol('IDENTITY_LOCK');
export const CLOCK = Symbol('CLOCK');

/** Injectable clock so waiting-period math is testable without real time. */
export type Clock = () => Date;

/**
 * GUC actor for writes performed by the workflow driver rather than a user
 * (contact-attempt sweeps). The audit event carries actorType 'system' with a
 * null actor; the version triggers get this sentinel because set_config needs
 * a value. No such user can exist: uuid v4 never produces the zero UUID.
 */
export const SYSTEM_ACTOR_ID = '00000000-0000-0000-0000-000000000000';
