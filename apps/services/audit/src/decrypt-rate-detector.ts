import type { ActorType } from '@estate/contracts';
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
 * for a still-breaching principal — the fail direction is an EXTRA event,
 * never a lost one (recorded in docs/03 §6q). An emit that fails is not
 * marked announced, so the next tick retries it: same fail direction.
 */

/** The one query. Windowed sweep over the partial index migration 002 added
 * (leading occurred_at — a pure time-range over all principals). The prefix
 * is token-safe by construction: detail values passed SAFE_TOKEN_PATTERN at
 * ingest, and split_part yields a substring. */
const DECRYPT_RATE_SQL = `
  SELECT split_part(detail->>'field', '.', 1) AS prefix,
         actor_type,
         actor_id,
         count(*)::int AS n
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
    rows: Array<{ prefix: string | null; actor_type: string; actor_id: string | null; n: number }>;
  }>;
}

export interface DecryptRateObservation {
  prefix: string;
  actorType: ActorType;
  actorId: string | null;
  count: number;
}

export interface DecryptRateBreach {
  boundName: BoundName;
  prefix: string;
  principal: PrincipalClass;
  actorType: ActorType;
  actorId: string | null;
  count: number;
  maxPerWindow: number;
}

/** Pure: observations in, breaches out. Breach = count STRICTLY exceeds. */
export function evaluateDecryptRates(
  observations: readonly DecryptRateObservation[],
): DecryptRateBreach[] {
  return observations.flatMap((o) => {
    const principal = principalClassOf(o.actorType, o.actorId);
    const bound = boundFor(o.prefix, principal);
    if (o.count <= bound.maxPerWindow) {
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
      },
    ];
  });
}

function episodeKey(b: DecryptRateBreach): string {
  return `${b.principal}|${b.actorId ?? 'none'}|${b.prefix}`;
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
      // A slow tick (hung query, slow broker) must not pile re-entrant ticks
      // onto the same connection; the next interval fires soon enough.
      return;
    }
    this.#running = true;
    try {
      const since = new Date(this.clock().getTime() - DECRYPT_WINDOW_SECONDS * 1000);
      const { rows } = await this.db.query(DECRYPT_RATE_SQL, [since]);
      const observations: DecryptRateObservation[] = rows.map((r) => ({
        // A decrypt event structurally carries detail.field; the fallback
        // token exists so a hand-inserted malformed row surfaces as an
        // unknown-prefix breach instead of an unemittable empty token.
        prefix: r.prefix && r.prefix.length > 0 ? r.prefix : 'missing_field',
        actorType: r.actor_type as ActorType,
        actorId: r.actor_id,
        count: r.n,
      }));
      const breaches = evaluateDecryptRates(observations);
      const current = new Set(breaches.map(episodeKey));
      for (const breach of breaches) {
        const key = episodeKey(breach);
        if (this.#announced.has(key)) {
          continue;
        }
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
          },
        });
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
      // An episode ends when its key stops breaching; dropping it re-arms.
      this.#announced = new Set([...this.#announced].filter((k) => current.has(k)));
    } catch (err) {
      this.#faults += 1;
      log({
        level: 'warn',
        msg: 'decrypt_rate_tick_failed',
        faults: this.#faults,
        error: err instanceof Error ? `${err.name}: ${err.message}` : 'unknown',
      });
    } finally {
      this.#running = false;
    }
  }
}
