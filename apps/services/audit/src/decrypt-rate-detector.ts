import { DECRYPT_FIELD_SUBJECTS, type ActorType } from '@estate/contracts';
import { AuditEmitter } from '@estate/audit-emitter';
import { log } from './logger';
import {
  boundFor,
  DECRYPT_WINDOW_SECONDS,
  principalClassOf,
  type BoundName,
  type PrincipalClass,
} from './decrypt-rate-bounds';

/**
 * The M18 decrypt-rate detector (docs/03 §4 TB4, §6q).
 *
 * ADVISORY BY CONSTRUCTION — the settlement-driver pattern: it derives counts
 * from the append-only ledger by windowed query (no counter state an attacker
 * can reset), emits an audit event when a principal exceeds a reviewed bound,
 * and nothing anywhere acts on its output automatically. Losing it degrades
 * ALERTING, never safety, which is why every fault terminates in its own
 * catch + one structured log line and NEVER reaches the fatal handler —
 * a detector error killing the process would kill ingest, the paging signal,
 * for an advisory neighbour (the M9 rule both ways: a control firing is not
 * an outage, an outage is not an anomaly).
 *
 * THE COUNTED SET IS EXACTLY 'crypto.field.decrypted'. The anomaly action it
 * emits is structurally outside its own count (the M16 self-feeding-counter
 * rule) — the int suite proves that by ingesting an exceeded event and
 * asserting the next tick counts nothing new.
 *
 * EPISODES, NOT TICKS: a sustained breach emits once when it starts, stays
 * silent while it persists, and re-arms when the window clears. The episode
 * memory is per-process (#announced), so a restart may re-emit one duplicate
 * for a still-breaching principal, and an emit that fails leaves its key
 * un-announced so the next tick retries it.
 *
 * THE FAIL DIRECTION IS AN EXTRA EVENT, WITH ONE STATED EXCEPTION. The M18
 * review falsified the unqualified version of that claim twice over, and
 * both holes are closed above (per-emit catch, reconciliation that cannot be
 * skipped). What remains true and cannot be fixed here: a breach whose emit
 * keeps failing until its decrypts age out of the window is LOST, not late —
 * the retry is bounded by the window, so an emit outage longer than
 * DECRYPT_WINDOW_SECONDS loses the anomalies raised inside it. That is a
 * property of a windowed detector with a durable-nowhere queue, recorded in
 * docs/03 §6q rather than papered over; closing it needs the anomaly to be
 * persisted before it is emitted, which is a different design.
 */

/** The one query. Windowed sweep over the partial index migration 002 added
 * (leading occurred_at — a pure time-range over all principals). The prefix
 * is token-safe by construction: detail values passed SAFE_TOKEN_PATTERN at
 * ingest, and split_part yields a substring. */
/**
 * The distinct-subject expression, BUILT FROM `DECRYPT_FIELD_SUBJECTS` rather
 * than written out, so the segment index exists once. A prefix with no
 * declaration contributes NULL, which `count(DISTINCT …)` ignores — so it
 * reports 0 subjects and its bound, which carries no distinct condition, is
 * unaffected.
 *
 * Both interpolated values are checked before they reach the string: the keys
 * are TypeScript identifiers from a const object and the positions are small
 * integers, and a declaration that is neither fails at module load rather than
 * becoming SQL. That is cheap insurance on the one place in this service that
 * assembles a query from a table.
 *
 * The table is a PARAMETER (defaulted to the real one) purely so those refusals
 * and the empty case are reachable from a test. Validation nothing can trigger
 * is validation nobody has read — the M13 round-3 rule — and a throw on a
 * module-load path is the worst place to discover that.
 */
export function distinctSubjectExpression(
  subjects: Record<string, number | undefined> = DECRYPT_FIELD_SUBJECTS,
): string {
  const whens = Object.entries(subjects).map(([prefix, at]) => {
    if (!/^[a-z][a-z0-9_]*$/.test(prefix)) {
      throw new Error(`decrypt-rate detector: unusable subject prefix ${JSON.stringify(prefix)}`);
    }
    if (at === undefined || !Number.isInteger(at) || at < 1 || at > 8) {
      throw new Error(`decrypt-rate detector: unusable subject position for ${prefix}`);
    }
    return `WHEN '${prefix}' THEN split_part(detail->>'field', '.', ${at})`;
  });
  if (whens.length === 0) {
    // No declarations ⇒ nothing to count, and `CASE END` with no WHEN is a
    // syntax error. NULL keeps every distinct count at 0, which is the
    // never-suppress default.
    return 'NULL';
  }
  return `CASE split_part(detail->>'field', '.', 1) ${whens.join(' ')} END`;
}

/**
 * Exported for the int spec ONLY. `count(DISTINCT CASE …)` is the one piece of
 * this detector no unit test can prove — the segment index lives in a SQL
 * string, and whether Postgres extracts the subject the declaration names is a
 * question only Postgres answers. The int spec runs THIS constant rather than a
 * copy of it, so a divergence is impossible by construction.
 */
export const DECRYPT_RATE_SQL = `
  SELECT split_part(detail->>'field', '.', 1) AS prefix,
         actor_type,
         actor_id,
         count(*)::int AS n,
         count(DISTINCT ${distinctSubjectExpression()})::int AS distinct_subjects
    FROM audit_events
   WHERE action = 'crypto.field.decrypted'
     AND occurred_at >= $1
   GROUP BY 1, 2, 3`;

/** Minimal query port; the pg Client satisfies it. The detector holds its OWN
 * dedicated connection — the ingestor's serialized client must never be
 * shared (its chain-head row lock and transaction live on one session). */
export interface DetectorDb {
  query(
    text: string,
    values: unknown[],
  ): Promise<{
    rows: Array<{
      prefix: string | null;
      actor_type: string;
      actor_id: string | null;
      n: number;
      distinct_subjects?: number;
    }>;
  }>;
}

export interface DecryptRateObservation {
  prefix: string;
  actorType: ActorType;
  actorId: string | null;
  count: number;
  /** Distinct subjects touched; 0 for a prefix that declares no subject. */
  distinctSubjects: number;
}

export interface DecryptRateBreach {
  boundName: BoundName;
  prefix: string;
  principal: PrincipalClass;
  actorType: ActorType;
  actorId: string | null;
  count: number;
  maxPerWindow: number;
  /** Carried into the emitted detail only when the bound has the condition. */
  distinctSubjects?: number;
  maxDistinctSubjectsPerWindow?: number;
}

/**
 * Pure: observations in, breaches out.
 *
 * Breach = the count STRICTLY exceeds its bound AND — where the bound carries
 * the second condition — the distinct-subject count strictly exceeds its own.
 * AND, not OR, and the asymmetry is the point: the distinct condition exists
 * to SUPPRESS the one legitimate pattern a count cannot describe (a large
 * estate read repeatedly), never to raise an alarm the count did not.
 *
 * It cannot introduce blindness the count bound did not already have. A
 * principal touching N distinct subjects has made at least N decrypts, so
 * distinct ≤ count always; with both thresholds equal, anything that clears
 * the count bound on DISTINCT rows clears the distinct bound too. What it
 * suppresses is exactly re-reading — which moves no plaintext the principal
 * had not already seen.
 */
export function evaluateDecryptRates(
  observations: readonly DecryptRateObservation[],
): DecryptRateBreach[] {
  return observations.flatMap((o) => {
    const principal = principalClassOf(o.actorType, o.actorId);
    const bound = boundFor(o.prefix, principal);
    if (o.count <= bound.maxPerWindow) {
      return [];
    }
    const maxDistinct = bound.maxDistinctSubjectsPerWindow;
    if (maxDistinct !== undefined && o.distinctSubjects <= maxDistinct) {
      return [];
    }
    return [
      {
        boundName: bound.name,
        prefix: o.prefix,
        principal,
        actorType: o.actorType,
        actorId: o.actorId,
        count: o.count,
        maxPerWindow: bound.maxPerWindow,
        ...(maxDistinct === undefined
          ? {}
          : {
              distinctSubjects: o.distinctSubjects,
              maxDistinctSubjectsPerWindow: maxDistinct,
            }),
      },
    ];
  });
}

function episodeKey(b: DecryptRateBreach): string {
  return `${b.principal}|${b.actorId ?? 'none'}|${b.prefix}`;
}

/**
 * Collapse the SQL's rows onto the grain the BOUNDS use.
 *
 * The sweep groups by (prefix, actor_type, actor_id) because those are
 * columns; the bound and the episode key are keyed on the PRINCIPAL CLASS,
 * which folds the nil-UUID sentinel's two actor types ('service' for
 * notification sends, 'system' for projection rebuilds) into one principal.
 * Left unmerged those arrive as two rows that each sit under the bound while
 * their sum exceeds it — one detector, two disagreeing notions of "a
 * principal", and the disagreement is an evasion path (the M18 review).
 *
 * Merging keeps the ROW's actorType for the emitted detail (the first
 * contributing row's — an attribution hint, not the grain).
 */
export function mergeObservations(
  rows: readonly {
    prefix: string | null;
    actor_type: string;
    actor_id: string | null;
    n: number;
    distinct_subjects?: number;
  }[],
): DecryptRateObservation[] {
  const merged = new Map<string, DecryptRateObservation>();
  for (const row of rows) {
    // A decrypt event structurally carries detail.field; the fallback token
    // exists so a hand-inserted malformed row surfaces as an unknown-prefix
    // breach instead of an unemittable empty token.
    const prefix = row.prefix && row.prefix.length > 0 ? row.prefix : 'missing_field';
    const actorType = row.actor_type as ActorType;
    const key = `${prefix}|${principalClassOf(actorType, row.actor_id)}|${row.actor_id ?? 'none'}`;
    // SUMMING DISTINCT COUNTS OVER-COUNTS, deliberately. Two merged rows may
    // have touched the same subject, so the sum is an UPPER BOUND on the true
    // distinct count — which errs toward breaching, the direction a
    // suppressing condition must fail in. An exact answer would need the
    // subjects themselves rather than their count, which is a far larger
    // result set for a number that only decides between "alarm" and "alarm
    // suppressed" on rows the sentinel merge produces (and no sentinel bound
    // carries the distinct condition today).
    const distinct = row.distinct_subjects ?? 0;
    const existing = merged.get(key);
    if (existing) {
      existing.count += row.n;
      existing.distinctSubjects += distinct;
      continue;
    }
    merged.set(key, {
      prefix,
      actorType,
      actorId: row.actor_id,
      count: row.n,
      distinctSubjects: distinct,
    });
  }
  return [...merged.values()];
}

export class DecryptRateDetector {
  /** Episode keys already announced; cleared per key when its breach clears. */
  #announced = new Set<string>();
  #faults = 0;
  #running = false;

  constructor(
    private readonly db: DetectorDb,
    private readonly emitter: AuditEmitter,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  /** Faults since boot — observability only, never a trigger. */
  get faults(): number {
    return this.#faults;
  }

  async tick(): Promise<void> {
    if (this.#running) {
      // A slow tick must not pile re-entrant ticks onto the same connection;
      // the next interval fires soon enough. The connection carries its own
      // query timeout (detector-connection.ts), so a black-holed socket
      // rejects and faults rather than latching this flag forever — without
      // that bound this guard IS the silent-death mode (the M18 review).
      return;
    }
    this.#running = true;
    try {
      const since = new Date(this.clock().getTime() - DECRYPT_WINDOW_SECONDS * 1000);
      let rows;
      try {
        ({ rows } = await this.db.query(DECRYPT_RATE_SQL, [since]));
      } catch (err) {
        // A failed READ yields no observations, so there is nothing to
        // reconcile against — episode memory is left exactly as it was and
        // the next tick re-derives it. Returning here (rather than falling
        // into a shared catch) is what keeps the reconciliation below
        // unreachable-by-failure.
        this.#fault('decrypt_rate_tick_failed', err);
        return;
      }
      const observations = mergeObservations(rows);
      const breaches = evaluateDecryptRates(observations);
      const current = new Set(breaches.map(episodeKey));

      // RECONCILE BEFORE EMITTING. The M18 review's worst finding was that
      // this ran AFTER the emit loop inside the same try, so one failed emit
      // skipped it: a principal whose episode had cleared stayed marked
      // announced, and its NEXT genuine episode was suppressed as a duplicate
      // — a LOST anomaly, in a detector whose docs promised the fail
      // direction was always an extra event.
      //
      // WHICH HALF IS LOAD-BEARING, measured rather than assumed: mutating
      // this line back below the loop leaves the suite GREEN, because the
      // per-emit catch below already stops a throw from escaping. The catch
      // is the fix; this ordering is the belt — it keeps the reconciliation
      // unreachable-by-failure even if someone later adds a statement to the
      // loop that can throw outside that catch.
      this.#announced = new Set([...this.#announced].filter((k) => current.has(k)));

      for (const breach of breaches) {
        const key = episodeKey(breach);
        if (this.#announced.has(key)) {
          continue;
        }
        try {
          await this.emitter.emit({
            action: 'crypto.decrypt_rate.exceeded',
            actorId: null,
            actorType: 'system',
            onBehalfOf: null,
            resourceType: 'decrypt_rate',
            // The breaching principal is the subject of the event.
            resourceId: breach.actorId,
            sessionId: null,
            detail: {
              boundName: breach.boundName,
              principal: breach.principal,
              actorType: breach.actorType,
              prefixClass: breach.prefix,
              count: breach.count,
              bound: breach.maxPerWindow,
              windowSeconds: DECRYPT_WINDOW_SECONDS,
              // Present only when the bound carries the second condition, so
              // whoever reads this can tell "read a lot" from "read a lot of
              // DIFFERENT things" — which is the whole difference between a
              // large estate and an exfiltration. Counts and thresholds only:
              // the subjects themselves are entity ids and stay out of the
              // trail's detail, exactly as every other event here.
              ...(breach.maxDistinctSubjectsPerWindow === undefined
                ? {}
                : {
                    distinctSubjects: breach.distinctSubjects ?? 0,
                    distinctBound: breach.maxDistinctSubjectsPerWindow,
                  }),
            },
          });
        } catch (err) {
          // PER-EMIT, so one unemittable breach cannot cancel its neighbours
          // (the same review finding, second harm). The key stays
          // un-announced, so the next tick retries it while the breach lasts.
          this.#fault('decrypt_rate_emit_failed', err);
          continue;
        }
        this.#announced.add(key);
        // Decision 5: the alert sink is the audit action PLUS a structured
        // log line. Scalars only; ids and enums, never values.
        log({
          level: 'warn',
          msg: 'decrypt_rate_exceeded',
          boundName: breach.boundName,
          principal: breach.principal,
          prefixClass: breach.prefix,
          count: breach.count,
          bound: breach.maxPerWindow,
          actorId: breach.actorId ?? 'none',
        });
      }
    } finally {
      this.#running = false;
    }
  }

  #fault(msg: string, err: unknown): void {
    this.#faults += 1;
    log({
      level: 'warn',
      msg,
      faults: this.#faults,
      error: err instanceof Error ? `${err.name}: ${err.message}` : 'unknown',
    });
  }
}
