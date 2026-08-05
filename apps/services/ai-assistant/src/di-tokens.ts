/** Nest injection tokens for non-class providers. */
export const CONFIG = Symbol('CONFIG');
export const PG_POOL_CONFIG = Symbol('PG_POOL_CONFIG');
export const AUDIT_PRODUCER = Symbol('AUDIT_PRODUCER');
export const FIELD_CRYPTO = Symbol('FIELD_CRYPTO');
export const DEK_REPOSITORY = Symbol('DEK_REPOSITORY');
/** The model-provider port (deterministic stub in PR1; no live provider yet). */
export const LLM_GATEWAY = Symbol('LLM_GATEWAY');
/** Cedar PDP over the shared in-repo policy bundle. Deny by default. */
export const POLICY_DECISION_POINT = Symbol('POLICY_DECISION_POINT');
export const CLOCK = Symbol('CLOCK');

// NOTE: there is deliberately NO service-credential token here, in either
// direction, and its absence is the design rather than an oversight. Inbound,
// this service authenticates callers on their own bearer through
// @estate/auth-guard's session verification — it exposes no internal route for
// a peer to open, so no inbound credential exists to bind. Outbound, it reads
// its peers by FORWARDING that same caller bearer (the M8 PR5 BFF pattern), so
// it can only ever see what the caller could already see and can never mint
// authority it was not handed. That matters more here than anywhere else in
// the product: this is the one process an attacker can address in natural
// language, through document text and OCR output it is asked to read
// (docs/03 §4 TB5, risk #6). A static credential in this file would be a key
// that opens another service's internal routes, sitting behind the largest
// prompt-injection surface we have — the M7 credential collapse and the M9
// one-credential-two-capabilities finding are both what that looks like when
// it goes wrong. The trust graph is declared as data and machine-checked in
// packages/auth-guard/src/credential-graph.ts; this service must stay absent
// from it as a HOLDER.

/** Injectable clock so turn timestamps and retention math are testable. */
export type Clock = () => Date;

/**
 * GUC actor for writes performed by this service rather than by a user — work
 * with no session behind it, such as a retention sweep over expired
 * conversations. The audit events carry actorType 'service' with a null actor;
 * the version triggers get this sentinel because set_config needs a value. Same
 * value as assets/documents/notifications/settlement, and no such user can
 * exist: uuid v4 never produces the zero UUID.
 */
export const SYSTEM_ACTOR_ID = '00000000-0000-0000-0000-000000000000';
