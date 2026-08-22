import { useEffect, useRef, useSyncExternalStore } from 'react';
import { gqlRequest, type GqlResult, type OperationSignatures } from './client';
import { onOperationSuccess } from './operation-events';
import type { OperationName } from './operations';

/**
 * THE SHARED CLIENT READ CACHE (M24 PR1) — the capability docs/03 §6v said
 * this app does not have, shipped with its first consumer
 * (`UnverifiedAddressBanner`).
 *
 * What it is: one shared answer per enrolled operation, subscribed to with
 * `useSharedRead`, deduplicated while in flight, and INVALIDATED when a
 * mutation changes the fact it caches — at which point every mounted
 * subscriber re-reads from the server. The authority stays the SERVER: an
 * invalidation never patches a value, it discards one and asks again (the
 * ConsentControls rule, kept).
 *
 * ENROLLMENT IS AN ALLOWLIST, AND THE BAR IS WRITTEN HERE. A read may enroll
 * only if BOTH hold:
 *
 * 1. It is not an audited decrypt and carries no decrypted PII. Every
 *    content/PII read spends a logged KMS decrypt on the owner's trail, and a
 *    cache serving one from memory makes the repeat read invisible to that
 *    trail — the audited-decrypt UI constraint (.claude/rules/frontend.md).
 *    Status enums, counts and non-PII aggregates qualify; `Contact`,
 *    `DocumentContent`, `EstateDistributionAmount` and their kind never will.
 * 2. It takes NO VARIABLES. Keying is by operation name alone, so a
 *    parameterized read has no correct slot — the compile-time check below
 *    refuses the enrollment rather than trusting a serializer this module
 *    deliberately does not have.
 *
 * `read-cache.test.tsx` pins the enrolled set EXACTLY, so growing it is a
 * reviewed decision against this bar, never a drive-by.
 */
export const CACHED_OPERATIONS = ['EmailVerification'] as const;

export type CachedOperationName = (typeof CACHED_OPERATIONS)[number];

/**
 * Enrolled operations must be parameterless — see enrollment bar (2) above.
 * `EmptyVariables` in client.ts is `Record<string, never>`; an enrollment
 * whose variables carry a key turns this alias into `never` and the constant
 * below stops compiling.
 */
type EnrolledAreParameterless =
  OperationSignatures[CachedOperationName]['variables'] extends Record<string, never>
    ? true
    : never;
const enrolledAreParameterless: EnrolledAreParameterless = true;
void enrolledAreParameterless;

/**
 * WHICH MUTATIONS INVALIDATE WHICH READS — data, in one place, applied by the
 * transport's own success announcement so no ceremony call site holds the
 * duty. The §6v banner residual was exactly a forgot-to-tell-the-reader
 * defect; a convention asking every future ceremony to remember an
 * invalidate call would rebuild it one ceremony later.
 *
 * Both entries vouch for an address: `VerifyEmail` redeems the verification
 * code, and `CompleteEmailChange` moves the address AND vouches for the new
 * one in the same statement (§6v — redeeming the code proved the mailbox).
 * `CancelEmailChange` and `ResendEmailVerification` are deliberately absent:
 * neither changes what `emailVerification` answers.
 */
const INVALIDATED_BY: Partial<Record<OperationName, readonly CachedOperationName[]>> = {
  VerifyEmail: ['EmailVerification'],
  CompleteEmailChange: ['EmailVerification'],
};

type CachedResult = GqlResult<OperationSignatures[CachedOperationName]['data']>;

/** Present key = an answer a subscriber may render. Absent = nothing yet. */
const entries = new Map<CachedOperationName, CachedResult>();

/**
 * Supersede tokens. A fetch records its token at dispatch and writes its
 * result only if still current — an invalidation mid-flight bumps the token,
 * so an answer read BEFORE the mutation can never land AFTER it and be
 * mistaken for fresh.
 */
const fetchTokens = new Map<CachedOperationName, number>();

/**
 * The token of the latest DISPATCHED fetch. A fetch is genuinely pending only
 * while this equals the current supersede token — an invalidation with no
 * subscriber bumps the token without dispatching, which correctly reads as
 * "nothing pending" to the next mount.
 */
const pendingTokens = new Map<CachedOperationName, number>();

function isPending(name: CachedOperationName): boolean {
  const pending = pendingTokens.get(name);
  return pending !== undefined && pending === fetchTokens.get(name);
}

/** How many mounted hooks are watching each operation. */
const subscriberCounts = new Map<CachedOperationName, number>();

const listeners = new Set<() => void>();

function emitChange(): void {
  for (const listener of [...listeners]) {
    listener();
  }
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function startFetch(name: CachedOperationName): void {
  const token = (fetchTokens.get(name) ?? 0) + 1;
  fetchTokens.set(name, token);
  pendingTokens.set(name, token);
  void gqlRequest(name, {}).then((result) => {
    if (fetchTokens.get(name) !== token) {
      // Superseded — a newer fetch or an invalidation owns the slot now.
      return;
    }
    pendingTokens.delete(name);
    entries.set(name, result);
    emitChange();
  });
}

/**
 * Discard the cached answer — it is known wrong, so unlike a revalidation the
 * old value must NOT keep rendering while the fresh one is fetched — and
 * re-read for whoever is watching. With no subscriber mounted there is
 * nothing to refresh FOR; the next mount fetches.
 */
export function invalidateSharedRead(name: CachedOperationName): void {
  // Bump even when not refetching: an in-flight answer predates the mutation.
  fetchTokens.set(name, (fetchTokens.get(name) ?? 0) + 1);
  entries.delete(name);
  emitChange();
  if ((subscriberCounts.get(name) ?? 0) > 0) {
    startFetch(name);
  }
}

/**
 * Re-read while KEEPING the current answer visible until the fresh one lands
 * — the navigation case, where the old answer is merely old, not known wrong.
 * This is what preserves the banner's pre-cache rendering exactly.
 */
function revalidateSharedRead(name: CachedOperationName): void {
  startFetch(name);
}

onOperationSuccess((operation) => {
  for (const name of INVALIDATED_BY[operation] ?? []) {
    invalidateSharedRead(name);
  }
});

/**
 * Subscribe to one enrolled read. Returns the shared answer, or null while
 * nothing has arrived — and null is NO DATA, never data: a subscriber must
 * render its nothing-yet state, not a default that could be mistaken for an
 * answer (a failed read is not an empty one).
 *
 * `revalidateKey`: when this changes between renders, the read is re-asked
 * with the old answer left visible until the new one lands. The banner passes
 * the pathname, keeping its documented one-query-per-navigation freshness —
 * the cache changes WHO shares the answer and WHEN it is discarded, not how
 * often the server is asked.
 */
export function useSharedRead<Name extends CachedOperationName>(
  name: Name,
  options?: { revalidateKey?: string | undefined },
): GqlResult<OperationSignatures[Name]['data']> | null {
  // With one enrolled operation, the entry type IS the per-name type, so no
  // assertion is needed here. Enrolling a second operation makes this line a
  // compile error — the right speed bump: narrowing by `name` becomes a real
  // claim at that point and must be written (and argued) deliberately.
  const result = useSyncExternalStore(
    subscribe,
    () => entries.get(name) ?? null,
    () => null,
  );

  useEffect(() => {
    subscriberCounts.set(name, (subscriberCounts.get(name) ?? 0) + 1);
    // Single-flight: the second mount of a pair finds the first's fetch
    // pending and shares its answer instead of dispatching a duplicate.
    if (!entries.has(name) && !isPending(name)) {
      startFetch(name);
    }
    return () => {
      subscriberCounts.set(name, (subscriberCounts.get(name) ?? 0) - 1);
    };
  }, [name]);

  const revalidateKey = options?.revalidateKey;
  const seenKey = useRef(revalidateKey);
  useEffect(() => {
    if (seenKey.current !== revalidateKey) {
      seenKey.current = revalidateKey;
      revalidateSharedRead(name);
    }
  }, [name, revalidateKey]);

  return result;
}

/**
 * Harness-only: tests share this module instance, and a cache carried between
 * tests is a fixture nobody wrote. Never imported by product code.
 */
export function resetSharedReadsForTests(): void {
  entries.clear();
  fetchTokens.clear();
  pendingTokens.clear();
  subscriberCounts.clear();
}
