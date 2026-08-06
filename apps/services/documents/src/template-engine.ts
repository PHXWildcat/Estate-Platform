import { createHash, timingSafeEqual } from 'node:crypto';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { OBJECT_STORE } from './di-tokens';
import type { ObjectStore } from './object-store';
import { parseTemplateSource, type TemplateSource } from './template-model';
import type { TemplateRow } from './templates.repo';

export class TemplateIntegrityError extends Error {
  constructor() {
    super('template body failed integrity verification');
    this.name = 'TemplateIntegrityError';
  }
}

/**
 * How long a verified parse may be reused before its pin is checked again.
 *
 * THIS IS A DETECTION-LATENCY PARAMETER, not a performance knob, which is why
 * it is a reviewed constant rather than configuration: it is the longest a
 * swapped template body can sit in front of this process without
 * `document.template.integrity_failed` being emitted. Five minutes costs a
 * warm instance roughly twelve object-store reads per template per hour —
 * nothing against S3 — and bounds the blind spot at something a runbook can
 * state.
 */
export const TEMPLATE_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Hard bound on cached entries.
 *
 * The key is `(row id, sha)`, and publishing a new version mints a NEW ROW —
 * so the key space grows with every republication, for the life of the
 * process. Small in practice (a few KB per template, a catalog in the
 * hundreds) and unbounded in principle, which is the part worth closing.
 * Eviction is oldest-verified-first.
 */
export const TEMPLATE_CACHE_MAX_ENTRIES = 256;

interface CacheEntry {
  readonly source: TemplateSource;
  readonly verifiedAt: number;
}

/**
 * Loads a template row's body from the object store and verifies it against
 * the row's body_sha256 pin BEFORE parsing — a replaced or bit-rotted
 * template object fails closed instead of rendering someone an altered legal
 * instrument (docs/03 TB4 tamper adversary).
 *
 * ===========================================================================
 * WHY THE CACHE EXPIRES, AND WHAT THAT DOES AND DOES NOT FIX
 * ===========================================================================
 *
 * Parsed sources are cached by `(template id, sha)`. That key COMMITS TO THE
 * CONTENT: an entry can only ever be a parse whose bytes hashed to the sha in
 * its own key, and a published version is immutable, so a row's sha never
 * changes underneath it. The cache has therefore never been able to serve a
 * tampered parse — swap the object-store body and a warm process keeps serving
 * the legitimate one. This was never a correctness hole and is not being fixed
 * as though it were.
 *
 * WHAT IT COST WAS DETECTION. `body_sha256` exists to NOTICE tampering, and a
 * warm entry meant this process never looked at the object again — so the
 * swap went unremarked for the process's lifetime. That mattered little while
 * nothing acted on the signal. It matters now: M12 gave the check an audit
 * event (`document.template.integrity_failed`), and an alarm wired to a check
 * that only runs on cold starts is an alarm that mostly does not run. Expiry
 * turns "never re-verified in this process" into "re-verified at least every
 * TEMPLATE_CACHE_TTL_MS, by every replica" — a property a runbook can state
 * and a detection rule can rely on.
 *
 * THE CONSEQUENCE IS MORE FAIL-CLOSED, NOT LESS. Past the TTL, a tampered body
 * makes `load` throw where it used to quietly serve the good cached parse.
 * Every caller is already built for that throw: generation refuses,
 * `allowedTransitionsFor` degrades to de-escalation and audits, and the
 * catalog omits the template rather than offering an instrument nobody can
 * vouch for.
 *
 * WHAT THIS STILL DOES NOT DO, stated rather than implied: within one TTL a
 * swapped body is neither served nor noticed by an already-warm process.
 * Closing that completely means verifying on every load — N object-store reads
 * per catalog request on a user-facing route — and the trade is not worth it
 * for a detector whose job is to raise an alarm, not to gate each read. A
 * cold replica still detects immediately.
 */
@Injectable()
export class TemplateEngine {
  private readonly cache = new Map<string, CacheEntry>();

  constructor(
    @Inject(OBJECT_STORE) private readonly store: ObjectStore,
    /**
     * Injectable clock. `@Optional()` so Nest leaves it undefined and the
     * default applies — the engine is a plain provider with no clock token in
     * the container, and tests drive expiry rather than waiting for it.
     */
    @Optional() private readonly now: () => number = () => Date.now(),
  ) {}

  async load(row: TemplateRow): Promise<TemplateSource> {
    const shaHex = row.body_sha256.toString('hex');
    const cacheKey = `${row.id}:${shaHex}`;
    const at = this.now();
    const cached = this.cache.get(cacheKey);
    if (cached && at - cached.verifiedAt < TEMPLATE_CACHE_TTL_MS) {
      return cached.source;
    }
    const body = await this.store.get(row.body_ref);
    const digest = createHash('sha256').update(body).digest();
    if (digest.length !== row.body_sha256.length || !timingSafeEqual(digest, row.body_sha256)) {
      // A stale entry is DROPPED before the throw: leaving it would let the
      // next call inside the old TTL window serve a parse this one just
      // proved is no longer what the object store holds.
      this.cache.delete(cacheKey);
      throw new TemplateIntegrityError();
    }
    const source = parseTemplateSource(JSON.parse(body.toString('utf8')));
    // The row is the authority on identity; a body that disagrees with its
    // own row on (docType, state, version) is a publishing defect.
    if (
      source.docType !== row.doc_type ||
      source.state !== row.state ||
      source.version !== row.version
    ) {
      this.cache.delete(cacheKey);
      throw new TemplateIntegrityError();
    }
    this.remember(cacheKey, { source, verifiedAt: at });
    return source;
  }

  /** Insert, refreshing recency, and evict oldest-verified-first past the bound. */
  private remember(key: string, entry: CacheEntry): void {
    // delete-then-set moves an existing key to the end of Map iteration order,
    // so eviction below drops the least recently VERIFIED entry rather than
    // the one that happened to be inserted first.
    this.cache.delete(key);
    this.cache.set(key, entry);
    while (this.cache.size > TEMPLATE_CACHE_MAX_ENTRIES) {
      const oldest = this.cache.keys().next();
      if (oldest.done === true) {
        return;
      }
      this.cache.delete(oldest.value);
    }
  }
}

/** Deterministic object key for a template source. */
export function templateObjectKey(docType: string, state: string, version: number): string {
  return `templates/${state}/${docType}/v${version}.json`;
}
