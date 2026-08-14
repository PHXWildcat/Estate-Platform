import {
  DECRYPT_FIELD_PREFIXES,
  decryptFieldServiceFor,
  type ActorType,
  type DecryptFieldPrefix,
} from '@estate/contracts';

/**
 * Reviewed bounds for the M18 decrypt-rate baseline (docs/03 §4 TB4).
 *
 * DELIBERATELY NOT A LEARNED BASELINE: an attacker can train a learned one
 * and cannot train a reviewed commit (the M16/M17 rate-bounds rule). Every
 * number here is a constant set from the ceilings MEASURED in M18 PR1
 * (docs/04 M18 — a full stack-e2e journey plus a deliberate burst driver).
 * The docs/03 "normal × 50" framing is revised by this file: FIXED REVIEWED
 * CONSTANTS, NOT A FORMULA. Most rows sit at roughly ten windows' worth of
 * their measured peak, but that is a starting point rather than a rule — the
 * M18 review caught an earlier version of this comment stating it AS a
 * formula while two measured rows (notification_recipient, assistant_message)
 * deliberately sat well above it, so a reviewer sizing the next bound by
 * arithmetic would have computed numbers 5×–10× off. Each row's `note` is
 * where its own reasoning lives, and a row whose headroom is unusual says why
 * there.
 *
 * The GRAIN is (prefix class × principal class), counted per actorId — the
 * detector asks "did THIS principal exceed what THIS kind of reading is ever
 * legitimately worth", never "is the platform busy".
 *
 * FAIL-CLOSED-LOUD DEFAULTS: a (prefix × principal) combination this table
 * does not name has bound 0 — the first decrypt under it is reportable. An
 * unmodeled combination is not an outage and not noise; it is a read path
 * nobody reviewed (`unmodeled_principal`). Likewise an UNREGISTERED prefix
 * is bound 0 (`unknown_prefix`) — the registry fence cannot see a brand-new
 * prefix at review time (PR1 recorded why), so the detector is where it
 * becomes loud, and the stack e2e's zero-anomaly gate is what keeps that
 * loudness out of legitimate journeys.
 */

/** Shared by notifications 'service' sends and assets 'system' rebuilds. */
export const SENTINEL_ACTOR_ID = '00000000-0000-0000-0000-000000000000';

/**
 * The nil-UUID sentinel is its own principal class, never folded into the
 * actor type it happens to ride (decision 6): notifications sends arrive as
 * ('service', nil) and projection rebuilds as ('system', nil), and both are
 * "the platform acting with no session behind it" — a different thing to
 * baseline than any real principal.
 */
export type PrincipalClass = ActorType | 'sentinel';

export function principalClassOf(actorType: ActorType, actorId: string | null): PrincipalClass {
  return actorId === SENTINEL_ACTOR_ID ? 'sentinel' : actorType;
}

/**
 * One rolling window for every bound. A reviewed constant, not config (the
 * TEMPLATE_CACHE_TTL_MS rule): it is a detection-latency parameter, and it
 * changes by reviewed commit.
 */
export const DECRYPT_WINDOW_SECONDS = 300;

/** Detector cadence. Also a reviewed constant; tests never run the timer. */
export const DETECTOR_TICK_MS = 60_000;

/**
 * Query timeout for the detector's own session. Generous against the windowed
 * sweep (milliseconds in practice) and far tighter than the OS keepalive
 * interval, which is what a black-holed socket would otherwise wait out while
 * the detector's re-entrancy guard stayed latched and silent.
 */
export const DETECTOR_QUERY_TIMEOUT_MS = 30_000;

export interface DecryptRateBound {
  prefix: DecryptFieldPrefix;
  principal: PrincipalClass;
  /**
   * Peak observed per principal per MINUTE in the M18 PR1 measurement
   * (docs/04 M18). 0 = the class was not exercised by the journey; its bound
   * is provisional, sized from the neighbouring measured economics, and says
   * so in its note.
   */
  measuredPerMinute: number;
  /** Breach when the windowed count strictly EXCEEDS this. */
  maxPerWindow: number;
  note: string;
}

export const DECRYPT_RATE_BOUNDS: readonly DecryptRateBound[] = [
  // identity (auth cluster)
  {
    prefix: 'users',
    principal: 'user',
    measuredPerMinute: 0,
    maxPerWindow: 60,
    note: 'email decrypts on the change/notice paths only — rare by design',
  },
  {
    prefix: 'mfa_methods',
    principal: 'user',
    measuredPerMinute: 2,
    maxPerWindow: 100,
    note: "one secret decrypt per TOTP check. An earlier note claimed the M16 step-up bounds cap this transitively; the M18 review refuted it with this milestone's own e2e — those bounds count DENIALS since the last grant, so a caller holding a live session and one valid 30-second code drives successful step-ups (and their decrypts) at whatever rate identity sustains, which is precisely how the stack gate produces its 101-step-up burst. Nothing upstream caps the success path, so THIS bound is the cap",
  },
  // profile (core cluster)
  {
    prefix: 'profile',
    principal: 'user',
    measuredPerMinute: 50,
    maxPerWindow: 2500,
    note: '10 reads × 5 non-null fields measured',
  },
  {
    prefix: 'contact',
    principal: 'user',
    measuredPerMinute: 160,
    maxPerWindow: 8000,
    note: '20-contact estate: 3 lists + every detail read measured (the M13 economics)',
  },
  {
    prefix: 'family',
    principal: 'user',
    measuredPerMinute: 0,
    maxPerWindow: 2500,
    note: 'family reads decrypt every stored field by recorded decision (docs/03); unexercised by the journey — provisional, sized on the contact/profile economics',
  },
  // assets (financial cluster)
  {
    prefix: 'asset',
    principal: 'user',
    measuredPerMinute: 30,
    maxPerWindow: 1500,
    note: '5 lists × 5 valuations + 5 single reads measured; executor estate reads ride the same class by design',
  },
  {
    prefix: 'asset_event',
    principal: 'user',
    measuredPerMinute: 0,
    maxPerWindow: 1500,
    note: 'asset history decrypts one payload per ledger event — scales with ledger length; provisional, sized on asset',
  },
  {
    prefix: 'asset_event',
    principal: 'sentinel',
    measuredPerMinute: 0,
    maxPerWindow: 5000,
    note: 'projection rebuild replays the whole LEDGER as the sentinel; a full rebuild of a large estate trips this BY DESIGN — a mass decrypt is the detected class, and the operator running one expects the alarm (docs/03 §6q)',
  },
  {
    prefix: 'asset',
    principal: 'sentinel',
    measuredPerMinute: 0,
    maxPerWindow: 5000,
    note: "the rebuild's SECOND decrypt site: diffing the live projection reads assets_view columns as asset.<id>.<col>, still as the sentinel (rebuild.service.ts diffView). Missing until the M18 review, which made every rebuild of any valued estate emit unmodeled_principal at count 1 — the loudest class in the table, fired by a reviewed path, which is exactly how an alarm stops being read. Sized with its ledger twin so a large rebuild still trips ONE designed alarm rather than an accidental one",
  },
  // documents (documents cluster)
  {
    prefix: 'doc',
    principal: 'user',
    measuredPerMinute: 10,
    maxPerWindow: 500,
    note: 'one audited decrypt per content read, measured',
  },
  {
    prefix: 'doc',
    principal: 'operator',
    measuredPerMinute: 0,
    maxPerWindow: 60,
    note: 'M7 evidence reads — the one operator decrypt in the product (attribution fixed in M18 PR1); rare by construction',
  },
  // plaid (financial cluster)
  {
    prefix: 'plaid_item',
    principal: 'service',
    measuredPerMinute: 0,
    maxPerWindow: 100,
    note: 'token decrypts at sync/revoke only, actorType service with the owner as actorId (plaid.service decryptAccessToken)',
  },
  {
    prefix: 'account',
    principal: 'user',
    measuredPerMinute: 0,
    maxPerWindow: 500,
    note: 'one balance decrypt per account row per list read; provisional, sized on asset economics',
  },
  // ai-assistant (core cluster)
  {
    prefix: 'assistant_message',
    principal: 'user',
    measuredPerMinute: 2,
    maxPerWindow: 1000,
    note: 'history rebuild decrypts every prior turn on each turn — scales with conversation length',
  },
  {
    prefix: 'assistant_tool_call',
    principal: 'user',
    measuredPerMinute: 0,
    maxPerWindow: 1000,
    note: 'tool-result re-derivation rides the same per-turn history pass; provisional, sized on assistant_message',
  },
  // notifications (core cluster)
  {
    prefix: 'notification_recipient',
    principal: 'sentinel',
    measuredPerMinute: 16,
    maxPerWindow: 4000,
    note: 'address resolution per send, always the sentinel; scales with platform activity, sized for the local deployment this ships against',
  },
];

/**
 * Prefixes with NO legitimate decrypt reader at all, listed with reasons so
 * the zero is a visible decision rather than an inference from absence. Any
 * decrypt under one of these breaches immediately (`encrypt_only`).
 */
export const ENCRYPT_ONLY_PREFIXES: Partial<Record<DecryptFieldPrefix, string>> = {
  distributions:
    'settlement amounts are write-only — no read route exists (M18 PR1 corrected the comment that claimed otherwise); the first decrypt ever observed under this prefix is the anomaly',
};

export type BoundName =
  | `${DecryptFieldPrefix}_${PrincipalClass}`
  | 'encrypt_only'
  | 'unmodeled_principal'
  | 'unknown_prefix';

export interface ResolvedBound {
  name: BoundName;
  maxPerWindow: number;
}

/**
 * Resolve the bound for one (prefix, principal) pair. Total: every input
 * resolves, and everything outside the reviewed table resolves to 0 — the
 * loud default, never the permissive one (the M8 fail-open-in-style rule).
 */
export function boundFor(prefix: string, principal: PrincipalClass): ResolvedBound {
  if (decryptFieldServiceFor(prefix) === null) {
    return { name: 'unknown_prefix', maxPerWindow: 0 };
  }
  const registered = prefix as DecryptFieldPrefix;
  if (Object.prototype.hasOwnProperty.call(ENCRYPT_ONLY_PREFIXES, registered)) {
    return { name: 'encrypt_only', maxPerWindow: 0 };
  }
  const row = DECRYPT_RATE_BOUNDS.find((b) => b.prefix === registered && b.principal === principal);
  if (!row) {
    return { name: 'unmodeled_principal', maxPerWindow: 0 };
  }
  return { name: `${row.prefix}_${row.principal}`, maxPerWindow: row.maxPerWindow };
}

/** Registered prefixes with neither a bound row nor an encrypt-only reason
 * would silently inherit the 0 default; the spec derives this set and
 * asserts it is empty, so every registered prefix carries a VISIBLE decision. */
export function undecidedPrefixes(): string[] {
  return Object.keys(DECRYPT_FIELD_PREFIXES).filter(
    (prefix) =>
      !DECRYPT_RATE_BOUNDS.some((b) => b.prefix === prefix) &&
      !Object.prototype.hasOwnProperty.call(ENCRYPT_ONLY_PREFIXES, prefix),
  );
}
