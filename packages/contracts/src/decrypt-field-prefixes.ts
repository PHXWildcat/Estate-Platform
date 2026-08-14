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
 * WHERE THE SUBJECT'S ID SITS IN A FIELD NAME — 1-based, `split_part` order.
 *
 * The header above calls the id tail "cardinality, not class", which is right
 * for attribution and wrong for detection: HOW MANY DISTINCT THINGS a principal
 * decrypted is the closest thing the audit stream holds to "how much data left
 * the envelope". A fixed count bound cannot tell a 120-asset estate browsed
 * seven times (1680 decrypts, 120 subjects) from a mass read of 1680 different
 * assets (1680 decrypts, 1680 subjects) — MEASURED, and the first of those
 * raised the TB4 alarm on a legitimate owner reading their own estate through
 * the product's own pages.
 *
 * DELIBERATELY SPARSE, and the empty entries are the point rather than an
 * omission. A declaration here lets a bound SUPPRESS an alarm, so a wrong one
 * is a blind spot: every entry is verified against the field's own construction
 * in the owning service, and `test/decrypt-field-subjects.spec.ts` re-checks
 * that against source. Anything not named here is counted, never suppressed.
 *
 * `doc` is the cautionary entry and is deliberately ABSENT. Its field is
 * `doc.<ownerUserId>.v<n>.<sha>` (documents/content-cipher.ts), so segment 2 is
 * the OWNER — the same value for every document a person holds. Sampling the
 * live stream shows a UUID there and invites exactly the wrong declaration,
 * which would collapse an owner's whole library to one subject and suppress a
 * mass document read. The position is read from the code that builds the
 * string, never from what the data looks like.
 */
export const DECRYPT_FIELD_SUBJECTS: Partial<Record<DecryptFieldPrefix, number>> = {
  // `asset.<assetId>.<column>` — assets.service.ts viewField(). The one prefix
  // whose legitimate volume scales with the size of the owner's estate rather
  // than with their activity, and so the one that needs this.
  asset: 2,
};

/**
 * The subject id inside a field name, or null when this prefix declares none.
 *
 * Same hasOwnProperty guard as `decryptFieldServiceFor`, and for the same
 * reason: field names are attacker-adjacent strings, so `constructor` must not
 * resolve through the prototype into a segment index.
 */
export function decryptFieldSubject(field: string): string | null {
  const prefix = decryptFieldPrefix(field);
  // ONE guard, not two: "the prefix is not declared" and "it is declared as
  // undefined" are the same answer — no position — and splitting them left the
  // second arm unreachable by any test, which is a branch nobody has read.
  const at = Object.prototype.hasOwnProperty.call(DECRYPT_FIELD_SUBJECTS, prefix)
    ? DECRYPT_FIELD_SUBJECTS[prefix as DecryptFieldPrefix]
    : undefined;
  if (at === undefined) {
    return null;
  }
  const segment = field.split('.')[at - 1];
  return segment !== undefined && segment.length > 0 ? segment : null;
}

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
