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
 *   2. EVERY READER of `emergency_access_policies` filters that table's own
 *      `deleted_at IS NULL` — derived from the SQL the runtime sends, so a
 *      sixth reader joins this fence by EXISTING and a rename does not move
 *      it. The first version of this file said `lockLive*` here and filtered
 *      the corpus by that prefix, so three of the five readers were outside
 *      it (M27 PR5). Demonstrated rather than argued: adding an unfiltered
 *      sixth reader left the fence green at 6/6.
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
import { readdirSync, readFileSync } from 'node:fs';
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

// ------------------------------------------- the reader corpus, from the SQL

const TABLE = 'emergency_access_policies';

/** Floors, MEASURED (13 statements / 5 readers / 8 writers) and set below. */
const MIN_POLICY_STATEMENTS = 12;
const MIN_POLICY_READERS = 5;
const MIN_POLICY_WRITERS = 6;

/**
 * SQL line comments out, load-bearing for the same reason the TS stripper is:
 * without it a comment reading `-- deleted_at IS NULL is handled by the caller`
 * satisfies the tombstone test, which is this repo's Cedar-fence failure one
 * layer down. Removed rather than flattened, because `002` carries a trailing
 * comment containing a `;` and flattening cut a CREATE TABLE in half.
 */
function stripSqlComments(sql: string): string {
  return sql
    .split('\n')
    .map((line) => {
      const at = line.indexOf('--');
      return at === -1 ? line : line.slice(0, at);
    })
    .join('\n');
}

const flat = (text: string): string => text.replace(/\s+/g, ' ').trim();

interface PolicyStatement {
  /** file + enclosing method. A LABEL for the failure message, never a filter. */
  readonly at: string;
  /** The statement as Postgres receives it. */
  readonly sql: string;
}

/** Every SQL literal in `src` naming the policy table. THE WHOLE DIRECTORY. */
function policyStatements(): PolicyStatement[] {
  const out: PolicyStatement[] = [];
  const names = new RegExp(`\\b${TABLE}\\b`, 'i');
  for (const file of readdirSync(SRC_DIR).filter((f) => f.endsWith('.ts'))) {
    const src = stripComments(readFileSync(join(SRC_DIR, file), 'utf8'));
    const decls = [...src.matchAll(/\basync\s+([A-Za-z_$][\w$]*)\s*\(/g)];
    for (const m of src.matchAll(/`([^`]*)`/g)) {
      const sql = flat(stripSqlComments(m[1] ?? ''));
      if (!names.test(sql)) continue;
      const owner = decls.filter((d) => d.index < (m.index ?? 0)).pop();
      out.push({ at: `${file} ${owner ? `${owner[1]}()` : '(top level)'}`, sql });
    }
  }
  return out;
}

/**
 * `FROM`/`JOIN` of the policy table with the alias it binds — `''` when bare,
 * `null` when the statement does not read the table at all.
 *
 * THE KEYWORD GUARD IS WHAT MAKES THE BARE FORM READABLE: after
 * `FROM emergency_access_policies` the next token is either an alias or a
 * clause keyword, and without the guard `WHERE` is captured as the alias. The
 * two floors on alias FORM are the anti-vacuity for exactly this — a guard that
 * mis-parses in either direction moves one of them to zero.
 */
const FROM_POLICIES = new RegExp(
  String.raw`\b(?:FROM|JOIN)\s+${TABLE}\b` +
    String.raw`(?:\s+(?:AS\s+)?(?!WHERE\b|LEFT\b|RIGHT\b|FULL\b|INNER\b|CROSS\b|NATURAL\b|JOIN\b|ON\b|USING\b|GROUP\b|ORDER\b|HAVING\b|LIMIT\b|OFFSET\b|FOR\b|UNION\b|EXCEPT\b|INTERSECT\b|RETURNING\b|SET\b|VALUES\b)([A-Za-z_][\w$]*))?`,
  'gi',
);

function aliasOf(sql: string): string | null {
  const found = [...sql.matchAll(FROM_POLICIES)];
  return found.length === 0 ? null : (found[0]?.[1] ?? '');
}

/**
 * Does the statement filter THIS TABLE'S OWN tombstone? ALIAS-AWARE, and that
 * is not decoration: `listByGrantee` joins `emergency_access_configs`, so a
 * bare /deleted_at IS NULL/ would also be satisfied by a query whose only
 * tombstone filter belonged to the JOINED table. It passes for the right reason
 * TODAY — the filter really is `p.deleted_at IS NULL` and the join partner has
 * no `deleted_at` at all — which is exactly why a bare test would go on passing
 * after either of those facts changed.
 */
function filtersTombstone(sql: string, alias: string): boolean {
  return alias === ''
    ? /(?<![\w.])deleted_at\s+IS\s+NULL\b/i.test(sql)
    : new RegExp(String.raw`\b${alias}\.deleted_at\s+IS\s+NULL\b`, 'i').test(sql);
}

/**
 * THE READER'S IDENTITY, AND IT IS NOT ITS NAME: the WHERE clause it sends,
 * terms sorted and alias qualifiers dropped. A rename of the method or of the
 * alias leaves it untouched; a change to WHAT the query selects on does not.
 */
function predicateOf(sql: string): string {
  const tail = /\bWHERE\b(.*?)(?:\bORDER\s+BY\b|\bLIMIT\b|\bRETURNING\b|$)/is.exec(sql)?.[1] ?? '';
  return flat(tail)
    .replace(/\bFOR\s+UPDATE\b/gi, '')
    .split(/\bAND\b/i)
    .map((term) => flat(term).replace(/\b[A-Za-z_][\w$]*\./g, ''))
    .filter(Boolean)
    .sort()
    .join(' AND ');
}

interface PolicyReader extends PolicyStatement {
  readonly alias: string;
  readonly predicate: string;
  readonly locks: boolean;
}

const POLICY_STATEMENTS = policyStatements();

const POLICY_READERS: PolicyReader[] = POLICY_STATEMENTS.flatMap((s) => {
  const alias = aliasOf(s.sql);
  return alias === null
    ? []
    : [{ ...s, alias, predicate: predicateOf(s.sql), locks: /\bFOR\s+UPDATE\b/i.test(s.sql) }];
});

const POLICY_WRITERS = POLICY_STATEMENTS.filter(
  (s) => !POLICY_READERS.some((r) => r.at === s.at && r.sql === s.sql),
);

/**
 * THE RECORDED SET — the predicates the runtime sends, not a hand-list of
 * names. A sixth reader changes this; a rename does not. Its job is only "the
 * population moved": the tombstone itself is the assertion below, so a filter
 * that switched to the JOINED table changes nothing here and reddens there.
 * Written down rather than computed, for the reason `session-audience.spec.ts`
 * gives of `EXTENSION_ROUTES` — deriving it from the readers would make it
 * agree with any widening automatically.
 */
const EXPECTED_POLICY_READERS: readonly string[] = [
  'deleted_at IS NULL AND grantee_user_id = $1',
  'deleted_at IS NULL AND grantee_user_id = $2 AND id = $1 FOR UPDATE',
  'deleted_at IS NULL AND id = $1 AND user_id = $2 FOR UPDATE',
  "deleted_at IS NULL AND status = 'released' AND user_id = $1",
  'deleted_at IS NULL AND user_id = $1',
];

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

  it('the SQL scan found both halves of the corpus it reasons over', () => {
    // ANTI-VACUITY AT EVERY LEVEL, because mis-attribution preserves totals —
    // including on alias FORM, which is what proves the keyword guard parses
    // both spellings rather than collapsing one into the other.
    expect(POLICY_STATEMENTS.length).toBeGreaterThanOrEqual(MIN_POLICY_STATEMENTS);
    expect(POLICY_READERS.length).toBeGreaterThanOrEqual(MIN_POLICY_READERS);
    expect(POLICY_WRITERS.length).toBeGreaterThanOrEqual(MIN_POLICY_WRITERS);
    expect(POLICY_READERS.filter((r) => r.alias !== '').length).toBeGreaterThanOrEqual(1);
    expect(POLICY_READERS.filter((r) => r.alias === '').length).toBeGreaterThanOrEqual(3);
  });

  it('CONTROL: the alias handling is load-bearing, not decoration', () => {
    // The one case a bare /deleted_at IS NULL/ accepts and this refuses — a
    // reader whose only tombstone filter belongs to the JOINED table.
    const joined = (tombstone: string): string =>
      `SELECT p.id FROM ${TABLE} p LEFT JOIN emergency_access_configs c` +
      ` ON c.user_id = p.user_id WHERE p.grantee_user_id = $1 AND ${tombstone}`;
    expect(filtersTombstone(joined('p.deleted_at IS NULL'), 'p')).toBe(true);
    expect(/deleted_at IS NULL/.test(joined('c.deleted_at IS NULL'))).toBe(true);
    expect(filtersTombstone(joined('c.deleted_at IS NULL'), 'p')).toBe(false);
    // And the alias is READ OFF the SQL rather than assumed.
    expect(aliasOf(joined('p.deleted_at IS NULL'))).toBe('p');
    expect(aliasOf(`SELECT id FROM ${TABLE} WHERE id = $1`)).toBe('');
    expect(aliasOf(`UPDATE ${TABLE} SET status = 'revoked' WHERE id = $1`)).toBeNull();
  });

  it('is filtered out by EVERY reader of the table, whatever it is called', () => {
    // THE SET, so a sixth reader is a decision somebody records here rather
    // than a silent gap. Keyed on the PREDICATE the runtime sends: the name
    // prefix this replaced left three of five readers outside the corpus.
    expect(
      POLICY_READERS.map((r) => `${r.predicate}${r.locks ? ' FOR UPDATE' : ''}`).sort(),
    ).toEqual([...EXPECTED_POLICY_READERS].sort());

    expect(
      POLICY_READERS.filter((r) => !filtersTombstone(r.sql, r.alias)).map(
        (r) => `${r.at}: ${r.sql}`,
      ),
    ).toEqual([]);
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
