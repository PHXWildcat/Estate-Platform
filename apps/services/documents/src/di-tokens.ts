/** Nest injection tokens for non-class providers. */
export const CONFIG = Symbol('CONFIG');
export const PG_POOL_CONFIG = Symbol('PG_POOL_CONFIG');
export const AUDIT_PRODUCER = Symbol('AUDIT_PRODUCER');
export const FIELD_CRYPTO = Symbol('FIELD_CRYPTO');
export const DEK_REPOSITORY = Symbol('DEK_REPOSITORY');
export const POLICY_DECISION_POINT = Symbol('POLICY_DECISION_POINT');
export const OBJECT_STORE = Symbol('OBJECT_STORE');
export const CLOCK = Symbol('CLOCK');

/** Injectable clock so time-dependent logic is testable without real time. */
export type Clock = () => Date;
