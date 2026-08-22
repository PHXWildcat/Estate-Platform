/**
 * THE ERASURE PARTICIPANT SET (M25).
 *
 * Crypto-shredding is the repo's only lawful deletion primitive: destroy the
 * DEK, never the row (docs/02 conventions, docs/03 §6kk). A DEK exists in every
 * service that holds a KEK, so "which domains must an erasure reach" has a
 * mechanical answer — the services with a non-null `kekAlias` in
 * `apps/stack/src/topology.ts` — and this constant is that answer written down
 * where both the identity driver and the DDL can use it.
 *
 * A HAND-LIST IS THIS REPO'S MOST REPEATED DEFECT, so it is pinned from two
 * independent directions rather than trusted. `erasure-domains.spec.ts` derives
 * the set from the topology AND from the `erasure_domain_progress` DDL's own
 * CHECK vocabulary, and compares all three AS SETS: a ninth KEK-holding service
 * turns that fence red until it is named here and in the migration. Sets, not
 * counts — a swap preserves a count and changes the meaning.
 *
 * MEMBERSHIP HERE IS NOT A CLAIM THAT THE DOMAIN CAN BE ERASED. M25 ships
 * identity's own destroy leg; the other seven have no transport to ask yet, and
 * a request accordingly does not reach `completed`. That gap is the point of
 * the ledger: it is a row per domain saying which half happened.
 */
export const ERASURE_DOMAINS = [
  'identity',
  'profile',
  'assets',
  'plaid',
  'documents',
  'settlement',
  'notifications',
  'ai-assistant',
] as const;

export type ErasureDomain = (typeof ERASURE_DOMAINS)[number];

/**
 * Per-domain progress states, mirroring the `erasure_domain_progress` CHECK.
 *
 * Two values, because two are producible today. 'refused' and 'failed' are real
 * states in the design and arrive with the fan-out that can write them — a
 * vocabulary listing values nothing produces is dormant, and widening a CHECK
 * later needs no pre-flight.
 */
export const ERASURE_DOMAIN_STATES = ['pending', 'done'] as const;

export type ErasureDomainState = (typeof ERASURE_DOMAIN_STATES)[number];

/**
 * Request lifecycle, mirroring the `erasure_requests.status` CHECK.
 *
 * `completed` means EVERY domain in the ledger reported done — it is not
 * "as much as this build knows how to erase". A terminal state whose meaning
 * changes at the next deploy is worse than one that is honestly not yet
 * reachable, so the definition is fixed here and the reach is what grows.
 */
export const ERASURE_REQUEST_STATUSES = ['pending', 'cancelled', 'executing', 'completed'] as const;

export type ErasureRequestStatus = (typeof ERASURE_REQUEST_STATUSES)[number];
