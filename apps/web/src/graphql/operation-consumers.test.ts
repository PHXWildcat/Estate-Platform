import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { operations } from './operations';

/**
 * EVERY OPERATION HAS A CALLER (M20 PR4) — the route↔consumer fence's shape,
 * one layer up, at the GraphQL surface.
 *
 * Why it exists: the `Refresh` operation shipped in M8 at every layer — SDL,
 * BFF resolver, identity client, operations.ts, the persisted manifest — and
 * was called by NOTHING for twelve milestones, while the access token's
 * 15-minute TTL was the whole usable session. An operation nobody calls is
 * dead weight at best; at worst it is a capability (a persisted, allowlisted
 * document the BFF will execute) whose behavior no test on the product path
 * ever exercises.
 *
 * DELIBERATELY NO EXEMPTION MECHANISM (the M20 PR3 rule: a named empty
 * exemption invites the next entry to reuse it without re-arguing). An
 * operation belongs in operations.ts in the same change as its first caller —
 * exactly the discipline `ROUTE_CONSUMERS` enforces for service routes. If a
 * future PR genuinely must stage an operation ahead of its caller, it can
 * argue with this fence in review, where the argument belongs.
 *
 * The REVERSE direction — every gqlRequest names a real operation — is the
 * compiler's: `OperationName` is a closed union, so a typo or a removed
 * operation with a surviving caller fails `tsc`, not this scan.
 *
 * COMMENTS ARE STRIPPED PROPERLY, which the first version did not do. It was
 * line-based and dropped only lines beginning with a slash-slash, a star, or a
 * slash-star — so a line INSIDE a block comment that did not happen to start
 * with a star survived, and a commented-out `gqlRequest('Foo'` in one counted
 * as a product caller (M20 PR5). The docstring called this "a commented-out
 * caller on a shared line", understating it: whole paragraphs were being
 * read as code. Block comments go first, then line comments, which is the
 * `code()` helper every other fence in this repo uses.
 *
 * Stated limit, and it is now the small one it was claimed to be: a
 * commented-out caller sharing a line with real code would still count. The
 * failure direction is a fence too generous about ONE caller, never one that
 * goes quietly green with zero.
 */
describe('every GraphQL operation has a product caller', () => {
  const SRC_ROOT = join(__dirname, '..');

  function sourceFiles(dir: string, acc: string[] = []): string[] {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        // test-utils is harness, not product; a caller there proves nothing.
        if (entry.name !== 'test-utils') sourceFiles(path, acc);
      } else if (/\.(ts|tsx)$/.test(entry.name) && !/\.test\.(ts|tsx)$/.test(entry.name)) {
        acc.push(path);
      }
    }
    return acc;
  }

  function codeLines(file: string): string {
    return readFileSync(file, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/[^\n]*/g, '');
  }

  const files = sourceFiles(SRC_ROOT);
  const allCode = files.map(codeLines).join('\n');
  const names = Object.keys(operations);

  function occurrencesOf(needle: string): number {
    let count = 0;
    let index = allCode.indexOf(needle);
    while (index !== -1) {
      count += 1;
      index = allCode.indexOf(needle, index + 1);
    }
    return count;
  }

  /**
   * TWO SPELLINGS OF "a product caller", since M24 PR1: a direct
   * `gqlRequest('X', …)` and a shared-cache subscription `useSharedRead('X', …)`.
   * The cache's own internal `gqlRequest(name, {})` is generic and correctly
   * counts for nothing — a consumer is a call site that NAMES the operation.
   */
  function callersOf(name: string): number {
    return occurrencesOf(`gqlRequest('${name}'`) + occurrencesOf(`useSharedRead('${name}'`);
  }

  it('finds no operation without a caller', () => {
    const uncalled = names.filter((name) => callersOf(name) === 0);
    expect(uncalled).toEqual([]);
  });

  it('every document is a query or a mutation, so the retry classification is total', () => {
    // `gqlRequest` retries ONLY queries (a mutation's retry can re-run a
    // write-then-read-back resolver's write). It decides by reading the
    // document's leading keyword, so a document beginning with anything else
    // — a `subscription`, or a stray leading comment — would be classified as
    // a mutation by default. That default is the SAFE direction, and this
    // assertion is what keeps it from becoming a silent one.
    const odd = Object.entries(operations)
      .filter(([, doc]) => {
        const head = doc.trimStart();
        return !head.startsWith('query ') && !head.startsWith('mutation ');
      })
      .map(([name]) => name);
    expect(odd).toEqual([]);
    // Both kinds are really present — a scan that classified everything one
    // way would satisfy the assertion above vacuously.
    const queries = Object.values(operations).filter((d) => d.trimStart().startsWith('query '));
    expect(queries.length).toBeGreaterThanOrEqual(20);
    expect(queries.length).toBeLessThan(names.length);
  });

  it('is not vacuous: the scan sees the real surface', () => {
    // The operation map is the product's whole GraphQL vocabulary; a scan
    // that suddenly sees a fraction of it has broken, not improved.
    expect(names.length).toBeGreaterThanOrEqual(80);
    expect(files.length).toBeGreaterThanOrEqual(60);
    // Positive control on the matcher itself: Session is the most-called
    // operation in the app (three components read it).
    expect(callersOf('Session')).toBeGreaterThanOrEqual(3);
    // And the one this fence was built for: Refresh's caller is the client's
    // own refreshSession, which goes through the public gqlRequest entry.
    expect(callersOf('Refresh')).toBeGreaterThanOrEqual(1);
    // Positive control for the SECOND spelling (M24 PR1): the app-shell
    // banner subscribes to EmailVerification through the shared read cache.
    // Without this, the useSharedRead half of the matcher could go blind —
    // matching nothing — while every operation stayed green through its
    // gqlRequest count.
    expect(occurrencesOf(`useSharedRead('EmailVerification'`)).toBeGreaterThanOrEqual(1);
  });
});
