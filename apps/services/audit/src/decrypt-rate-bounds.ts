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
 * number here is a constant set from a ceiling MEASURED by a stack-e2e journey
 * plus a deliberate burst driver. Most were measured by M18 PR1's (docs/04
 * M18); a row a LATER journey first reached carries that milestone's number and
 * names it in its note — `asset_event`/`user` from M19 PR2, the two
 * `distributions` rows from M48 PR3. This paragraph said "MEASURED in M18 PR1"
 * of every row until M48 PR3, which was already false when M19 PR2 shipped.
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
   * Peak observed per principal per MINUTE when the stack e2e journey drives
   * this class. Most rows were measured by the M18 PR1 journey (docs/04 M18);
   * a row a LATER journey first reached names that milestone in its note,
   * because the number and the drive that produced it are one fact.
   *
   * 0 = no journey exercises the class at all; its bound is provisional,
   * sized from the neighbouring measured economics, and says so in its note.
   *
   * A SMALL non-zero number is not automatically a peak. Where a drive exists
   * to prove the path is reachable rather than to sample a workload, the row
   * says so and its bound is still sized from economics — reading such a 1 as
   * a workload and dividing into it is how a bound gets set 50x too tight.
   */
  measuredPerMinute: number;
  /** Breach when the windowed count strictly EXCEEDS this. */
  maxPerWindow: number;
  /**
   * A SECOND condition, and both must hold for a breach (see `boundFor`).
   *
   * Only meaningful for a prefix that declares a subject position
   * (`DECRYPT_FIELD_SUBJECTS`); undefined everywhere else, which means the
   * count alone decides exactly as it did before. Present ONLY where a
   * legitimate reading is high-count and low-subject — the pattern a count
   * bound cannot tell from a mass read, and the one this dimension exists for.
   *
   * It can only ever SUPPRESS an alarm, so adding it to a bound is a
   * deliberate narrowing that has to say why, in the note.
   */
  maxDistinctSubjectsPerWindow?: number;
  note: string;
}

export const DECRYPT_RATE_BOUNDS: readonly DecryptRateBound[] = [
  // identity (auth cluster)
  {
    prefix: 'users',
    principal: 'user',
    measuredPerMinute: 0,
    maxPerWindow: 60,
    note: 'exactly TWO producers: the change ceremony decrypting its staged copy, and the M24 PR2 reveal-on-demand address read — each a user-initiated act (no mount-time read, no list field), so the ceiling stays a hand-review number rather than a throughput grant. The M18 original said "change/notice paths only"; its notice producer never existed under this prefix — the old-address notice resolves through the notifications recipient store, whose decrypt is its own row below (M24 PR2 review)',
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
    maxDistinctSubjectsPerWindow: 1500,
    note:
      'TWO conditions, because a count alone cannot express this one. Legitimate volume here ' +
      'scales with ESTATE SIZE, which is unbounded, while every other bound in this table ' +
      'scales with activity: one /assets page load issues Assets + NetWorth together, so it ' +
      'costs 2 decrypts PER ASSET OWNED. MEASURED: seven ordinary page loads of a 120-asset ' +
      'estate produced 1680 asset decrypts in ~20s and raised this alarm on an owner reading ' +
      'their own estate through the product — and the 1500 was itself calibrated on the M19 ' +
      'PR2 journey, an estate of a handful of assets. Raising the count is not the fix: any ' +
      'constant false-positives some estate and blinds the detector for every smaller one. ' +
      'The DISTINCT bound is what separates the two readings — that same browsing touched 120 ' +
      'distinct assets, while a mass read of 1680 assets touches 1680. Re-reading a row you ' +
      'already read exfiltrates nothing new, so suppressing repetition costs no detection; ' +
      'the distinct bound sits at the count bound so a genuine mass read still breaches both. ' +
      'Per-shape economics: asset_list=1/VALUED row (a null est_value_ct is skipped before the ' +
      'sink, so no event is counted), net_worth=1/valued row, asset_read=4 per detail load; ' +
      'executor estate reads ride this class by design. Page shapes (re-derived M24 PR3): the ' +
      '/assets load issues Assets + NetWorth together (2 per valued asset), and the DASHBOARD — ' +
      'the landing page since M24 PR3 — issues the same pair on every signed-in mount, so ' +
      'ordinary sign-ins now spend that shape too; its estate-checks press adds four analyser ' +
      'list reads ON DEMAND (4 per valued asset per press, the analysers each list on the ' +
      'caller’s own bearer). All of these re-touch the SAME distinct assets, which is exactly ' +
      'what the distinct dimension suppresses; neither shape moves either constant',
  },
  {
    prefix: 'asset_event',
    principal: 'user',
    measuredPerMinute: 3,
    maxPerWindow: 1500,
    note:
      'TWO producers, and the second is the one the bound is really sized against. getHistory ' +
      'decrypts one payload per ledger event of ONE asset, strictly ON DEMAND (never prefetched, ' +
      'dropped to idle after any command — including a designation, M19 PR4) — a 3-event asset = ' +
      '3 decrypts in one press. replayForUser decrypts EVERY event of EVERY asset the owner ' +
      'holds, in one request, from GET /v1/assets?asOf= and GET /v1/net-worth?asOf= — so an ' +
      'estate past ~1500 lifetime ledger events trips this bound on a legitimate as-of read. ' +
      'The M19 PR2 note described only the first and was corrected by the PR4 review; the ' +
      'measured 3/min is a per-asset history press, NOT a ceiling on the as-of path',
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
    note: 'M7 evidence reads (attribution fixed in M18 PR1); rare by construction. This note said "the one operator decrypt in the product" until M48 PR3: M23 PR4b added a second, and M48 PR2 made it SAY operator instead of hardcoding user — so the sentence was false from 2026-08-21 and unfalsifiable until 2026-08-28. The set of operator decrypts is these rows, not a count in a note',
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
  // settlement (core cluster) — BOTH principal classes, because both reach the
  // one decrypt site. `distributionAmount` passes
  // `actorType: isOperator ? 'operator' : 'user'` (admin.service.ts), and until
  // M48 PR2 derived that flag it hardcoded 'user', so an operator's reveal was
  // recorded as the estate's own reader. Modelling one class and not the other
  // would leave the unmodelled half at `unmodeled_principal`/0 — breaching at
  // count 1 on a reviewed path, which is the `asset`/`sentinel` defect above.
  {
    prefix: 'distributions',
    principal: 'user',
    measuredPerMinute: 1,
    maxPerWindow: 300,
    note: "the EXECUTOR reconciling one estate. One reveal per deliberate click — the list type carries no amount field and nothing prefetches (docs/03 §6f) — and an executor cannot reach a second estate's distributions without being named executor of that estate on a case an operator has separately verified (`assertCaseVisible` asks `isExecutorOf`; MEASURED — no distribution surface consults the staged-access ladder, which answers for vault and assets rather than for settlement's own routes), so the legitimate ceiling is one estate's distribution set re-read a few times. MEASURED AT 1 BY THE M48 PR3 DRIVE, which is a proof of reach and not a workload sample: it reveals one amount once, so 1 is the floor this path costs and says nothing about the ceiling an executor reconciling an estate would need. Sized from doc_user's per-deliberate-act economics rather than by arithmetic on that 1 — which would put the bound at 50 and red the first afternoon anyone settles an estate",
  },
  {
    prefix: 'distributions',
    principal: 'operator',
    measuredPerMinute: 1,
    maxPerWindow: 60,
    note: "TIGHTER THAN THE EXECUTOR'S, and deliberately, because the reach differs rather than the act: an operator can open any verified case, so the same count means something else. Sized with doc_operator, its twin — the other operator decrypt in the product, also one-per-deliberate-act and also rare by construction. An operator crossing 60 amount reveals inside five minutes is enumerating estates, not checking the figure they are approving. Also measured at 1 by the M48 PR3 drive, with the same caveat as the row above: the drive proves both classes reach this route and are recorded under the right `actor_type`, which is what decides WHICH of these two rows applies",
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
 * THERE IS NO ENCRYPT-ONLY CLASS ANY MORE (M48 PR3).
 *
 * `ENCRYPT_ONLY_PREFIXES` held exactly one member for its whole life —
 * `distributions`, on the ground that "settlement amounts are write-only, no
 * read route exists". The claim was TRUE when written (M18 PR2, `eef5606`,
 * crediting M18 PR1 with correcting an earlier comment that asserted a route
 * which did not then exist); M23 PR4b then shipped
 * `distributionAmount`, and from 2026-08-21 every dual-control amount check an
 * operator made breached the loudest class in the table at count 1. That is the
 * `asset`/`sentinel` defect in a different token — a reviewed path firing the
 * alarm meant
 * for unreviewed ones, which is how an alarm stops being read.
 *
 * The construct is DELETED rather than emptied. An empty map leaves a branch
 * `boundFor` can never take, a `BoundName` member nothing can produce, and a
 * fence that loops zero times — all green, all meaningless. Deleting it also
 * strengthens `undecidedPrefixes`: every registered prefix must now carry a
 * BOUND ROW, not merely "a visible decision", so the next write-only column
 * cannot be waved through with a sentence.
 *
 * The cost, stated: a genuinely unreadable prefix no longer gets a distinct
 * alarm name and would resolve to `unmodeled_principal`. That is the right
 * trade while the class has zero correct instances, and the note on such a row
 * is where the "should never be read" claim belongs — beside a number, where a
 * reviewer meets it.
 */
export type BoundName =
  `${DecryptFieldPrefix}_${PrincipalClass}` | 'unmodeled_principal' | 'unknown_prefix';

export interface ResolvedBound {
  name: BoundName;
  maxPerWindow: number;
  /**
   * Undefined ⇒ the count alone decides, which is every bound but one. The
   * ZERO-defaults above never carry it: an unknown prefix and an unmodeled
   * principal must breach at the first decrypt, and a second condition could
   * only ever hold that back. (There was a THIRD until M48 PR3 — an
   * encrypt-only prefix — and this sentence still named it after the class was
   * deleted, which is the same stale-absolute shape that PR deleted it for.)
   */
  maxDistinctSubjectsPerWindow?: number;
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
  const row = DECRYPT_RATE_BOUNDS.find((b) => b.prefix === registered && b.principal === principal);
  if (!row) {
    return { name: 'unmodeled_principal', maxPerWindow: 0 };
  }
  return {
    name: `${row.prefix}_${row.principal}`,
    maxPerWindow: row.maxPerWindow,
    ...(row.maxDistinctSubjectsPerWindow === undefined
      ? {}
      : { maxDistinctSubjectsPerWindow: row.maxDistinctSubjectsPerWindow }),
  };
}

/**
 * Registered prefixes with no bound row would silently inherit the 0 default;
 * the spec derives this set and asserts it is empty, so every registered prefix
 * carries a REVIEWED NUMBER. Stronger than it was: until M48 PR3 a prefix could
 * also discharge this by naming itself encrypt-only in a prose map, and the one
 * prefix that did so was wrong for two milestones without anything noticing.
 */
export function undecidedPrefixes(): string[] {
  return Object.keys(DECRYPT_FIELD_PREFIXES).filter(
    (prefix) => !DECRYPT_RATE_BOUNDS.some((b) => b.prefix === prefix),
  );
}
