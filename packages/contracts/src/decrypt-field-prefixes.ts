/**
 * Decrypt-attribution registry (M18 PR1, docs/03 §4 TB4).
 *
 * The audit envelope carries no producing-service field (AuditEventSchema),
 * so the only way the decrypt-rate detector can attribute a
 * `crypto.field.decrypted` event to a service is the field name every
 * FieldCrypto call site already carries in `detail.field`. The FIRST DOTTED
 * TOKEN of that name is disjoint per service — a convention until this file,
 * a closed registry from it (the AUDIT_ACTIONS shape: grows one reviewed
 * entry at a time, in review).
 *
 * Two properties every entry inherits:
 *
 *  - The field string is AAD input (packages/crypto fieldAad), so an entry
 *    here describes bytes already authenticated into existing ciphertext.
 *    A prefix can be ADDED alongside a new column; renaming one is a
 *    re-encryption of every row under it, never an edit to this map.
 *
 *  - An UNREGISTERED prefix in the stream is never silently absorbed:
 *    `decryptFieldServiceFor` answers null and the detector treats that as
 *    its own reportable class with a deliberately low bound — a decrypt
 *    under a prefix nobody registered is itself the anomaly.
 *
 * Several services embed row ids in field names (asset.<id>.<col>,
 * doc.<owner>.vN.<sha>, plaid_item.access_token.<id>,
 * assistant_message.<id>.content) — always normalize through
 * `decryptFieldPrefix` before counting; the id tail is cardinality, not
 * class.
 */
export const DECRYPT_FIELD_PREFIXES = {
  // identity (auth cluster)
  users: 'identity',
  mfa_methods: 'identity',
  // profile (core cluster)
  profile: 'profile',
  contact: 'profile',
  family: 'profile',
  // assets (financial cluster)
  asset: 'assets',
  asset_event: 'assets',
  // documents (documents cluster). The DEK subject there is the DOCUMENT
  // (per-object keys), so the event's resourceId is a document id rather
  // than a user — the field prefix is the service-attribution signal either
  // way.
  doc: 'documents',
  // plaid (financial cluster, isolated KEK)
  plaid_item: 'plaid',
  account: 'plaid',
  // ai-assistant (core cluster)
  assistant_message: 'ai-assistant',
  assistant_tool_call: 'ai-assistant',
  // notifications (core cluster)
  notification_recipient: 'notifications',
  // settlement (core cluster). Encrypt-only today: no amount read route
  // exists, so ZERO decrypt events under this prefix is the legitimate
  // state. Registered anyway, so that if one ever appears it attributes to
  // settlement rather than to the unknown class.
  distributions: 'settlement',
} as const;

export type DecryptFieldPrefix = keyof typeof DECRYPT_FIELD_PREFIXES;
export type DecryptEmittingService = (typeof DECRYPT_FIELD_PREFIXES)[DecryptFieldPrefix];

/**
 * First dotted token of a decrypt field name — the registry key. A field
 * with no dot is its own prefix (no such field exists today; one would
 * classify as unknown unless someone registers it).
 */
export function decryptFieldPrefix(field: string): string {
  const dot = field.indexOf('.');
  return dot === -1 ? field : field.slice(0, dot);
}

/**
 * Owning service for a field name, or null ⇒ the unknown class. The
 * hasOwnProperty guard is load-bearing: field names are attacker-adjacent
 * strings, and a prefix like `constructor` or `toString` must classify as
 * unknown, never resolve through the object prototype.
 */
export function decryptFieldServiceFor(field: string): DecryptEmittingService | null {
  const prefix = decryptFieldPrefix(field);
  return Object.prototype.hasOwnProperty.call(DECRYPT_FIELD_PREFIXES, prefix)
    ? DECRYPT_FIELD_PREFIXES[prefix as DecryptFieldPrefix]
    : null;
}
