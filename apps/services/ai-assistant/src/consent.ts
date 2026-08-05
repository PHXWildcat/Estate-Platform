/**
 * Per-feature consent for the AI assistant (docs/01 §2.8, docs/03 §4 TB5:
 * "PII tokenization before any model call, per-feature user consent flags").
 *
 * The vocabulary is CLOSED and mirrors the CHECK constraint on
 * `assistant_consents.scope`. Widening it is a migration AND a code change,
 * which is the point: each scope is a distinct grant of a distinct slice of
 * estate data to a third-party model provider, and the two halves failing
 * apart is what a review would catch.
 *
 * DENY BY DEFAULT is structural rather than conventional. There is no
 * `granted` boolean anywhere — consent is the PRESENCE of an unrevoked row, so
 * a user who has never answered and a user who has revoked produce the same
 * empty set, and code that forgets to consult this module reads nothing rather
 * than reading a permissive default.
 */

export const CONSENT_SCOPES = [
  /**
   * The master switch. Every other scope is meaningless without it, so
   * `permits` requires it in addition to the specific scope — revoking this
   * one alone turns the assistant off without the user having to revoke five
   * things and without any caller needing to remember the rule.
   */
  'assistant.enabled',
  /** Structured asset facts: net worth, categories, in-trust %, funding status. */
  'assistant.assets',
  /** Non-identifying profile facts only: state of residence, marital status. */
  'assistant.profile',
  /** Document inventory: type, execution status, dates. Never content. */
  'assistant.documents.metadata',
  /**
   * The text of a GENERATED document, fetched one at a time on the user's own
   * bearer through the audited content route. Uploaded-document text is NOT in
   * this scope and has no read path at all in M10 (M4's OCR artifact is sealed
   * with no decrypt counterpart) — a future scope would be added here.
   */
  'assistant.documents.content',
] as const;

export type ConsentScope = (typeof CONSENT_SCOPES)[number];

const SCOPE_SET: ReadonlySet<string> = new Set<string>(CONSENT_SCOPES);

/** Narrow an untrusted string (a request body, a stored row) to a known scope. */
export function isConsentScope(value: string): value is ConsentScope {
  return SCOPE_SET.has(value);
}

/**
 * The single authority on whether a capability may run. Requires BOTH the
 * master switch and the specific scope, so there is no way to hold
 * `assistant.assets` alone and have it mean anything.
 *
 * Callers must not re-implement this test — the tool executor consults it once
 * per invocation and records the answer on `assistant_tool_calls`.
 */
export function permits(granted: ReadonlySet<ConsentScope>, required: ConsentScope): boolean {
  if (!granted.has('assistant.enabled')) {
    return false;
  }
  return granted.has(required);
}
