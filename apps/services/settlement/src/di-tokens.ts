/** Nest injection tokens for non-class providers. */
export const CONFIG = Symbol('CONFIG');
export const PG_POOL_CONFIG = Symbol('PG_POOL_CONFIG');
export const AUDIT_PRODUCER = Symbol('AUDIT_PRODUCER');
export const POLICY_DECISION_POINT = Symbol('POLICY_DECISION_POINT');
export const NOTIFIER = Symbol('NOTIFIER');
export const IDENTITY_LOCK = Symbol('IDENTITY_LOCK');
/** M9 PR2: the estate-wide legal hold, driven from case transitions. */
export const DOCUMENTS_HOLD = Symbol('DOCUMENTS_HOLD');
export const CLOCK = Symbol('CLOCK');
/** PR2: envelope encryption for distribution amounts ('settlement/kek'). */
export const FIELD_CRYPTO = Symbol('FIELD_CRYPTO');
export const DEK_REPOSITORY = Symbol('DEK_REPOSITORY');
// NOTE: no service-credential token here on purpose. The inbound credential is
// bound to @estate/auth-guard's shared SERVICE_CREDENTIAL token in app.module,
// and the outbound one is passed straight into HttpIdentityLock. A local
// second token for the same concept was declared here and never used; it is
// removed because an unused credential channel is where the next accidental
// aliasing hides (see credential-graph.ts).

/** Injectable clock so waiting-period math is testable without real time. */
export type Clock = () => Date;

/**
 * GUC actor for writes performed by the workflow driver rather than a user
 * (contact-attempt sweeps). The audit event carries actorType 'system' with a
 * null actor; the version triggers get this sentinel because set_config needs
 * a value. No such user can exist: uuid v4 never produces the zero UUID.
 */
export const SYSTEM_ACTOR_ID = '00000000-0000-0000-0000-000000000000';
