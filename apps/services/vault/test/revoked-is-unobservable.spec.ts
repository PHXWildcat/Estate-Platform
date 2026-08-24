/**
 * `status='revoked'` IS UNOBSERVABLE TO EVERY POLICY ROUTE, AND THAT IS WHY
 * NONE OF THEM REFUSES ON IT (M27 PR3b review).
 *
 * WHY THIS EXISTS. Five guards in `emergency.service.ts` tested a policy for
 * `status === 'revoked'` and refused with `policy_revoked` — two on the grantee
 * paths (`release`, `readAsGrantee`), one on the grantee request path
 * (`blockReason`), and two on the owner's (`deny`, `rearm`). All five were
 * DEAD, for one reason: `markRevoked` is the only writer of that status and it
 * sets `deleted_at` in the SAME statement, while the two lookups every policy
 * route goes through filter `deleted_at IS NULL`. The row never arrives.
 *
 * The first pass removed TWO of the five — exactly the two a LINE coverage
 * floor could see, because there the `throw` was the whole statement and the
 * line went uncovered. The other three sit on an `if` that executes on every
 * call and merely never takes its branch, which a line floor cannot see and the
 * 78% branch floor did not force. Removing two of five is this repo's own "a
 * rule applied to one member of a category is a rule half-applied", and it took
 * an adversarial pass over the PR description to notice, because the
 * description CLAIMED the category.
 *
 * WHAT THIS ASSERTS, and why it is the invariant rather than the removal. A
 * test that pinned "no `policy_revoked` appears in the service" would go green
 * for a tree where somebody added a sixth lookup that does NOT filter
 * `deleted_at` — the arms would be genuinely needed again and nothing would
 * say so. So the fence is on the two facts that make them unnecessary:
 *
 *   1. `markRevoked` soft-deletes IN THE SAME STATEMENT that writes the status,
 *      and is the only writer of it.
 *   2. EVERY `lockLive*` lookup filters `deleted_at IS NULL`.
 *
 * Break either and this goes red, which is the signal to put the refusals back
 * — not to delete the assertion.
 *
 * COMMENTS ARE STRIPPED BEFORE MATCHING, because this same review found the
 * Cedar fence matching the paragraph that EXPLAINED a narrowing rather than the
 * narrowing, and going green when the narrowing was deleted. The comment above
 * this line contains the literal `status='revoked'`; without stripping, the
 * "only one writer" assertion would be reading its own documentation.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC_DIR = join(__dirname, '..', 'src');
const REPO_PATH = join(SRC_DIR, 'emergency.repo.ts');
const SERVICE_PATH = join(SRC_DIR, 'emergency.service.ts');

/** Block and line comments out; string contents left alone. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
}

/**
 * Method bodies by name, by brace matching from `async <name>(`. Crude on
 * purpose: it must not need a parser, and every anti-vacuity check below exists
 * because a crude scan that stops matching is indistinguishable from a clean
 * result.
 */
function methodBodies(src: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of src.matchAll(/\basync\s+([A-Za-z_$][\w$]*)\s*\(/g)) {
    const name = m[1];
    if (name === undefined) continue;
    const open = src.indexOf('{', m.index + m[0].length - 1);
    if (open < 0) continue;
    let depth = 0;
    let end = -1;
    for (let i = open; i < src.length; i += 1) {
      const ch = src[i];
      if (ch === '{') depth += 1;
      else if (ch === '}') {
        depth -= 1;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end > open) out.set(name, src.slice(open, end + 1));
  }
  return out;
}

const REPO_RAW = readFileSync(REPO_PATH, 'utf8');
const REPO_SRC = stripComments(REPO_RAW);
const SERVICE_SRC = stripComments(readFileSync(SERVICE_PATH, 'utf8'));
const METHODS = methodBodies(REPO_SRC);

describe('the scan itself', () => {
  it('found the repo methods it is about to reason over', () => {
    // A floor AND two named members: a rename that empties the map would
    // otherwise satisfy every `for` loop below by iterating nothing.
    expect(METHODS.size).toBeGreaterThanOrEqual(8);
    expect([...METHODS.keys()]).toEqual(expect.arrayContaining(['markRevoked']));
  });

  it('stripping comments did not empty the corpus', () => {
    // The failure this guards is the Cedar fence's: strip too greedily and
    // every "does not contain" assertion below passes on an empty string.
    expect(REPO_SRC.length).toBeGreaterThan(REPO_RAW.length * 0.5);
    expect(REPO_SRC).toContain('deleted_at IS NULL');
    // POSITIVE CONTROL for the stripper: a comment really was removed.
    expect(REPO_RAW).toContain('/**');
    expect(REPO_SRC).not.toContain('/**');
  });
});

describe("`status='revoked'` cannot be read back", () => {
  it('is written by exactly one method, and that method soft-deletes in the SAME statement', () => {
    const writers = [...METHODS.entries()]
      .filter(([, body]) => /status\s*=\s*'revoked'/.test(body))
      .map(([name]) => name);
    expect(writers).toEqual(['markRevoked']);

    // Same STATEMENT, not merely same method: two statements in one
    // transaction would still be one commit, but a later refactor that split
    // them could reorder, and the whole argument is that no reader can ever
    // observe the status without the tombstone.
    const body = METHODS.get('markRevoked') ?? '';
    const statements = [...body.matchAll(/`([^`]*)`/g)].map((m) => m[1] ?? '');
    const both = statements.filter(
      (sql) => /status\s*=\s*'revoked'/.test(sql) && /deleted_at\s*=/.test(sql),
    );
    expect(both).toHaveLength(1);
  });

  it('is filtered out by EVERY live-policy lookup, not just the grantee one', () => {
    const lookups = [...METHODS.entries()].filter(([name]) => name.startsWith('lockLive'));

    // ANTI-VACUITY AT THIS LEVEL, not just the total: the half-applied removal
    // this fence exists for happened because somebody reasoned about the
    // grantee lookup and forgot the owner's. Assert the SET, so a third lookup
    // arriving is a decision somebody records here rather than a silent gap.
    expect(lookups.map(([name]) => name).sort()).toEqual([
      'lockLiveByIdForGrantee',
      'lockLiveByIdForOwner',
    ]);

    for (const [name, body] of lookups) {
      expect([name, /deleted_at IS NULL/.test(body)]).toEqual([name, true]);
    }
  });
});

describe('so no route refuses on it', () => {
  it('no `policy_revoked` refusal survives in the service', () => {
    // The consequence of the two facts above. Stated as its own assertion so a
    // reader who reintroduces one is told which invariant made it unnecessary.
    expect(SERVICE_SRC).not.toContain('policy_revoked');
  });

  it('and the search that says so is not a broken grep', () => {
    // POSITIVE CONTROL. `not.toContain` on a mis-read file passes perfectly.
    // These are the sibling refusals on the same guards, which must be found.
    expect(SERVICE_SRC).toContain('already_released');
    expect(SERVICE_SRC).toContain('denied_by_owner');
  });
});
