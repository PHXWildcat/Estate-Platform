/**
 * THE ADDRESS-KEYED ATTEMPT BOUND (M17) — per process, in memory, best effort.
 *
 * `rate-bounds.ts` carries the reasoning for why this is not on the ledger. The
 * short version is that the ledger cannot see most of what needs bounding:
 * `recordLoginFailure(null, …)` writes a NULL user for every identifier that
 * does not resolve, and register's duplicate path writes nothing at all, so a
 * user-keyed count is blind to address spraying and to account probing — the
 * two things an unauthenticated bound exists for. The selector that works is
 * the email blind index, and putting THAT in an append-only table with no
 * `dek_id` would permanently record a correlatable identifier for addresses
 * belonging to no account and no person we have any relationship with.
 *
 * WHAT IS STORED IS NOT THE BLIND INDEX. The map is keyed on a truncated
 * sha256 OF the blind index: 128 bits, so collisions among the tens of
 * thousands of live entries are not a thing that happens, and the process never
 * holds the platform's own correlatable identifier in a long-lived structure.
 * Nothing here is persisted, logged, or exposed on any route.
 *
 * A FIXED WINDOW, NOT A SLIDING ONE. A sliding window needs a timestamp per
 * attempt; this needs two numbers per address. The cost is the usual
 * fixed-window artefact — up to 2× the cap across a window boundary — which is
 * the right trade for a bound whose whole character is "best effort, and there
 * is a durable ceiling behind it".
 *
 * EVICTION FAILS OPEN, DELIBERATELY. The map is capacity-bounded, because a
 * caller submitting unique addresses would otherwise make the rate limiter
 * itself the memory-exhaustion vector. When it is full the least recently
 * touched entry goes, and an evicted address starts again at zero. Failing
 * CLOSED on eviction would be worse in the only way that matters: it would let
 * whoever fills the map deny logins to every user in the product. The residual
 * — an attacker can flush their own counter by spraying — is stated in
 * docs/03 §6k rather than hidden behind the word "bounded".
 */
import { createHash } from 'node:crypto';
import type { AddressBoundOptions } from './rate-bounds';

/** Bytes of sha256 kept as the map key. 128 bits. */
const KEY_BYTES = 16;

interface Window {
  /** Failures recorded in the current window. */
  count: number;
  /** When the current window began. */
  startedAt: number;
}

export class AddressAttemptBound {
  /**
   * Insertion order IS the recency order: `record` and `exhausted` delete and
   * re-set an entry they touch, so the oldest key is always the first one the
   * iterator yields. That is what makes eviction O(1) without a second
   * structure.
   */
  readonly #windows = new Map<string, Window>();

  constructor(
    private readonly options: AddressBoundOptions,
    private readonly clock: () => Date,
  ) {}

  /**
   * Whether this address has spent its budget.
   *
   * SAFE TO SHORT-CIRCUIT ON, which is the property that lets the caller refuse
   * before paying for Argon2id. The answer depends only on how many times this
   * ADDRESS has been submitted, which is existence-independent — an address
   * with no account reaches the cap on exactly the same schedule as one with —
   * so refusing early here cannot correlate with whether the account exists and
   * does not re-open the timing channel `dummyVerify` closes. The ACCOUNT-keyed
   * bound has the opposite property and is deliberately checked after the
   * verification rather than before it.
   */
  exhausted(blindIndex: Buffer): boolean {
    const window = this.#live(this.#key(blindIndex));
    return window !== null && window.count >= this.options.max;
  }

  /** Record one failed attempt against this address. */
  record(blindIndex: Buffer): void {
    const key = this.#key(blindIndex);
    const existing = this.#live(key);
    if (existing) {
      existing.count += 1;
      return;
    }
    this.#evictIfFull();
    this.#windows.set(key, { count: 1, startedAt: this.clock().getTime() });
  }

  /**
   * Forget this address — called on a SUCCESSFUL authentication, so a user who
   * fumbles twice and then gets it right does not spend the rest of the window
   * one attempt from a refusal. It mirrors the ledger bound's "count since the
   * last success" and is the same idea with one number instead of a subquery.
   */
  clear(blindIndex: Buffer): void {
    this.#windows.delete(this.#key(blindIndex));
  }

  /** Live entries. Test-facing only; the routes never ask. */
  get size(): number {
    return this.#windows.size;
  }

  /**
   * The entry for this key if its window has not lapsed, else null — deleting
   * the lapsed one on the way past, so a quiet address does not occupy capacity
   * until eviction reaches it. Touching an entry also refreshes its recency.
   */
  #live(key: string): Window | null {
    const existing = this.#windows.get(key);
    if (!existing) {
      return null;
    }
    if (this.clock().getTime() - existing.startedAt >= this.options.windowMs) {
      this.#windows.delete(key);
      return null;
    }
    // Re-insert to move it to the end of the iteration order (see #windows).
    this.#windows.delete(key);
    this.#windows.set(key, existing);
    return existing;
  }

  #evictIfFull(): void {
    while (this.#windows.size >= this.options.capacity) {
      const oldest = this.#windows.keys().next();
      if (oldest.done === true) {
        return;
      }
      this.#windows.delete(oldest.value);
    }
  }

  #key(blindIndex: Buffer): string {
    return createHash('sha256')
      .update(blindIndex)
      .digest('hex')
      .slice(0, KEY_BYTES * 2);
  }
}
