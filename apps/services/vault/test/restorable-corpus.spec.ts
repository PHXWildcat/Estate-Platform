/**
 * A SOFT-DELETED VAULT ITEM SAYS WHY, AND THE VOCABULARY COMES FROM THE DDL.
 *
 * WHY THIS EXISTS. `VaultService.deleteItem` and `VaultService.reset` retire
 * `vault_items` rows with a BYTE-IDENTICAL `deleted_at` write and mean opposite
 * things by it. `deleteItem` changes no key material, so the blob is still
 * openable. `reset` replaces the keyset and clears the recovery keypair in the
 * same transaction, so every row it retires is cryptographically dead — nobody,
 * including the owner, can ever decrypt one again. Before migration 004 nothing
 * in the row distinguished them, and the restore surface M27 ships would have
 * offered both: the owner clicks a row that cannot decrypt, and the failure
 * arrives as a silent AEAD error, a control firing wearing an outage's face.
 *
 * WHAT IT ASSERTS, in four legs that do not share an input.
 *
 *   A. THE VOCABULARY IS THE DDL'S. Parsed out of the CHECK constraint in the
 *      migrations corpus, never restated here. "A fixture that invents an enum
 *      tests the fixture."
 *   B. THE CORPUS IS THE WHOLE DIRECTORY, and exactly ONE file may define the
 *      constraint. This is the M24 categories.test.ts lesson, which cost a
 *      fence: migrations are append-only and checksummed, so a fence reading
 *      ONE named migration is frozen with that file forever — a later
 *      redefinition arrives as a NEW file and the fence parses the snapshot,
 *      green for the same reason it is wrong. Scanning the directory and
 *      demanding a single definition makes the redefining migration redden this
 *      instead.
 *   C. THE PARTITION IS TOTAL AND BOTH ARMS ARE POPULATED. Every vocabulary
 *      value is restorable or not, and neither side is empty. An empty
 *      restorable arm is a restore surface that can never offer anything; an
 *      empty unrestorable arm means the discriminator stopped discriminating,
 *      which is the state this migration exists to leave behind.
 *   D. EVERY WRITER SETS IT. Derived from the SQL TEXT in `src`, because the
 *      SQL is what the runtime reads — a fence keyed on the method name
 *      `softDelete` is renamed into invisibility, and this repo has paid for
 *      that three times. The set of reasons the live paths write is compared
 *      against the vocabulary as SETS, so a writer that switches from
 *      'vault_reset' to 'user_delete' is caught even though the count holds.
 *
 * WHICH LAYER THIS PROVES: the vocabulary and the writes, statically. It does
 * NOT prove the database refuses a bad row — that is the paired CHECK in
 * migration 004, and it is exercised by the PG-gated int suites. Both are
 * needed and they fail differently: this one goes red on an unwritten reason
 * during `pnpm test`; the CHECK goes red on a wrong one, only against Postgres.
 *
 * WHAT A RED ASSERTION MEANS: a soft-delete path can now retire a row whose
 * decryptability nobody recorded, or the vocabulary moved without the code
 * following. Never widen the parse to make it pass.
 *
 * THE BOUND, stated rather than discovered later. This binds a route's reason
 * to the route's own keyset behaviour. It does NOT bound WHICH rows a route
 * retires: a `deleteItem` that retired every item the user owns would label
 * them 'user_delete', which is CORRECT for a route that leaves the keyset
 * alone, and this file would stay green. That is a scope property, no fence in
 * M27 PR0 claims it, and the M27 PR0 review demonstrated the mutation — it
 * survives because it is unfaithful to this claim, not because the claim is
 * weak.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  DELETED_REASONS,
  REASON_DISPOSITION,
  RESTORABLE_REASONS,
  type DeletedReason,
} from '../src/items.repo';

const MIGRATIONS = join(__dirname, '..', 'migrations');
const SRC = join(__dirname, '..', 'src');

/**
 * Floors. Measured at four migrations and two `deleted_at` writers; set below
 * those so ordinary work does not trip them, and high enough that a scan
 * returning nothing cannot pass. Two regexes that quietly match nothing agree
 * perfectly.
 */
const MIN_MIGRATIONS = 4;
const MIN_ITEM_SOFT_DELETES = 2;

function migrationFiles(): { name: string; sql: string }[] {
  return readdirSync(MIGRATIONS)
    .filter((f) => f.endsWith('.sql'))
    .sort()
    .map((name) => ({ name, sql: readFileSync(join(MIGRATIONS, name), 'utf8') }));
}

/** Every `CHECK (deleted_reason IN (...))`, with the file that defines it. */
function reasonChecks(): { name: string; values: string[] }[] {
  const found: { name: string; values: string[] }[] = [];
  for (const { name, sql } of migrationFiles()) {
    // Comments quote the vocabulary too, so the scan is anchored on the
    // CONSTRAINT rather than on the token: a `--` line mentioning
    // 'deleted_reason IN' must not count as a definition.
    const stripped = sql
      .split('\n')
      .filter((line) => !line.trimStart().startsWith('--'))
      .join('\n');
    const re = /CHECK\s*\(\s*deleted_reason\s+IN\s*\(([^)]*)\)/gi;
    let m = re.exec(stripped);
    while (m !== null) {
      const values = (m[1] as string)
        .split(',')
        .map((v) => v.trim().replace(/^'|'$/g, ''))
        .filter(Boolean);
      found.push({ name, values });
      m = re.exec(stripped);
    }
  }
  return found;
}

/**
 * Remove block comments and whole-line `//` comments. A MENTION IS NOT A USE:
 * the docstrings here name the vocabulary in order to explain it, and an
 * earlier draft of this fence read those mentions as call sites.
 */
function stripComments(text: string): string {
  return text
    .replace(/\/\*[^]*?\*\//g, '')
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n');
}

/** Source statements that write `deleted_at` on `vault_items`. */
function itemSoftDeleteStatements(): { file: string; sql: string }[] {
  const out: { file: string; sql: string }[] = [];
  for (const file of readdirSync(SRC).filter((f) => f.endsWith('.ts'))) {
    const text = readFileSync(join(SRC, file), 'utf8');
    // Template literals holding one statement. Anchored on the SQL the driver
    // sends, not on the method wrapping it.
    for (const raw of text.match(/`[^`]*`/g) ?? []) {
      const sql = raw.slice(1, -1).replace(/\s+/g, ' ').trim();
      if (!/UPDATE vault_items/i.test(sql)) continue;
      if (!/SET[^]*deleted_at\s*=/i.test(sql)) continue;
      out.push({ file, sql });
    }
  }
  return out;
}

/**
 * The `ItemsRepo` methods whose SQL retires a `vault_items` row, BY NAME —
 * derived from the statement, never listed. The name is what a caller writes;
 * the SQL is what the runtime sends, so the SQL is the anchor and the name is
 * the result.
 */
function itemSoftDeleteWriters(): string[] {
  const text = readFileSync(join(SRC, 'items.repo.ts'), 'utf8');
  const names: string[] = [];
  // A method ends at a closing brace on the class-member indent. The
  // anti-vacuity floor below is what catches this parse if the file's shape
  // ever changes — a scan that stops matching reports zero and reads clean.
  const re = /async\s+([A-Za-z0-9_]+)\s*\(([^]*?)\n {2}\}/g;
  let m = re.exec(text);
  while (m !== null) {
    const body = (m[2] as string).replace(/\s+/g, ' ');
    if (/UPDATE vault_items/i.test(body) && /SET[^]*deleted_at\s*=/i.test(body)) {
      names.push(m[1] as string);
    }
    m = re.exec(text);
  }
  return names;
}

/**
 * Every call site of a discovered writer, with the reason it passes and whether
 * the method it sits in ALSO replaces the vault keyset.
 *
 * The keyset check is the behavioural anchor: replacing the keyset in the same
 * transaction that retires rows is what makes those rows undecryptable. It is
 * read from the enclosing method's own body, so neither the writer nor the
 * route is identified by a name this fence chose.
 */
function callSites(writers: readonly string[]): {
  file: string;
  method: string;
  reason: DeletedReason;
  destroysKeyset: boolean;
}[] {
  const out: {
    file: string;
    method: string;
    reason: DeletedReason;
    destroysKeyset: boolean;
  }[] = [];
  for (const file of readdirSync(SRC).filter((f) => f.endsWith('.ts') && f !== 'items.repo.ts')) {
    const text = stripComments(readFileSync(join(SRC, file), 'utf8'));
    // Split into method bodies at the class-member indent, so a call site can
    // be attributed to the route that contains it.
    const methodRe = /\n {2}(?:private |public |protected )?(?:async )?([A-Za-z0-9_]+)\s*\(/g;
    const starts: { name: string; at: number }[] = [];
    let mm = methodRe.exec(text);
    while (mm !== null) {
      starts.push({ name: mm[1] as string, at: mm.index });
      mm = methodRe.exec(text);
    }
    starts.forEach((start, i) => {
      const body = text.slice(start.at, starts[i + 1]?.at ?? text.length);
      const destroysKeyset = /keysets\.replace\s*\(/.test(body);
      for (const writer of writers) {
        const re = new RegExp(`\\.${writer}\\(([^;]*?)\\)\\s*;`, 'g');
        let m = re.exec(body);
        while (m !== null) {
          for (const lit of (m[1] as string).match(/'[^']*'/g) ?? []) {
            const value = lit.slice(1, -1);
            if ((DELETED_REASONS as readonly string[]).includes(value)) {
              out.push({
                file,
                method: start.name,
                reason: value as DeletedReason,
                destroysKeyset,
              });
            }
          }
          m = re.exec(body);
        }
      }
    });
  }
  return out;
}

describe('vault_items.deleted_reason — the restorable corpus comes from the DDL', () => {
  const checks = reasonChecks();

  it('exactly one migration defines the vocabulary, and the corpus is the whole directory', () => {
    // LEG B. Anti-vacuity first: a directory read that returned nothing would
    // make "exactly one definition" fail for the wrong reason, and a scan that
    // stopped matching would report zero and read as a clean sweep.
    expect(migrationFiles().length).toBeGreaterThanOrEqual(MIN_MIGRATIONS);
    expect(checks.map((c) => c.name)).toEqual(['004_vault_item_deleted_reason.sql']);
  });

  it('the vocabulary in code is the vocabulary in the DDL, as SETS', () => {
    // LEG A. Sets, not counts: a rename that swaps one value for another
    // preserves every total.
    // `at(-1)`, not `[0]`. Migrations are append-only, so the AUTHORITATIVE
    // definition is the newest — and leg B is what keeps there being only one,
    // while its own docstring describes a redefining migration as the expected
    // future event. Reading the oldest was inert today and a trap for whoever
    // extends leg B. Found by the M27 PR0 review.
    const ddl = [...(checks.at(-1)?.values ?? [])].sort();
    expect(ddl.length).toBeGreaterThan(0);
    expect([...DELETED_REASONS].sort()).toEqual(ddl);
  });

  it('the partition is total and BOTH arms are populated', () => {
    // LEG C. THE FIRST DRAFT OF THIS ASSERTION WAS A TAUTOLOGY, and the M27 PR0
    // review is what found it. It computed the unrestorable arm as the set
    // COMPLEMENT of the restorable one, so "the partition is total" held by
    // construction and a fourth DDL value defaulted silently into it — while
    // the comment above claimed the decision was forced. It was not.
    //
    // The disposition is now a total `Record<DeletedReason, …>`, so the real
    // forcing function is the COMPILER: a fourth vocabulary member fails
    // typecheck with TS2741 until it is classified. What is left for this test
    // is the half a type cannot check — that the map's keys are the DDL's
    // values at RUNTIME (a cast would satisfy the compiler and lie), and that
    // neither arm is empty.
    const ddl = [...(checks.at(-1)?.values ?? [])].sort();
    expect(Object.keys(REASON_DISPOSITION).sort()).toEqual(ddl);

    const arms = Object.values(REASON_DISPOSITION);
    expect(arms.filter((a) => a === 'restorable').length).toBeGreaterThan(0);
    expect(arms.filter((a) => a === 'unrestorable').length).toBeGreaterThan(0);
    expect([...RESTORABLE_REASONS].sort()).toEqual(
      ddl.filter((r) => REASON_DISPOSITION[r as keyof typeof REASON_DISPOSITION] === 'restorable'),
    );

    // The one classification worth pinning by name rather than by shape: a
    // reset-retired blob is dead, so it may never be offered for restore. If
    // this line is ever deleted, the arm it protects is the one that hands an
    // owner a row that cannot decrypt.
    expect(REASON_DISPOSITION.vault_reset).toBe('unrestorable');
  });

  it('every statement that retires a vault_items row also records why', () => {
    // LEG D. The category is the SQL, not the method name.
    const statements = itemSoftDeleteStatements();
    expect(statements.length).toBeGreaterThanOrEqual(MIN_ITEM_SOFT_DELETES);
    const silent = statements
      .filter((s) => !/deleted_reason\s*=/i.test(s.sql))
      .map((s) => `${s.file}: ${s.sql}`);
    expect(silent).toEqual([]);
  });

  it('each retirement route writes the reason its OWN behaviour implies', () => {
    // LEG D, SECOND HALF — REWRITTEN AFTER THE M27 PR0 REVIEW BROKE IT TWICE.
    //
    // Draft 1 scanned the whole of `src` for each literal. It survived
    // re-labelling `reset`'s rows 'user_delete' — the one change that offers
    // cryptographically dead blobs — because `'vault_reset'` is ALSO a session
    // revoke reason and a third vocabulary in `events.service.ts`. Three
    // alphabets share the token.
    //
    // Draft 2 read only the writers' call-site arguments, but UNIONED them into
    // one set before comparing. That proves both labels appear SOMEWHERE and
    // never that a given route writes the right one: the review demonstrated
    // two survivors, including a full swap of `deleteItem` and `reset`, with
    // the whole unit suite still green.
    //
    // So the anchor is now BEHAVIOUR, and it is the same fact the migration
    // rests on: a route that replaces the keyset in the transaction that
    // retires the rows has destroyed the ability to decrypt them. `reset` calls
    // `keysets.replace`; `deleteItem` does not. Nothing here is keyed on a
    // method NAME — both the writers and the enclosing routes are discovered.
    const writers = itemSoftDeleteWriters();
    expect(writers.length).toBeGreaterThanOrEqual(MIN_ITEM_SOFT_DELETES);

    const sites = callSites(writers);
    expect(sites.length).toBeGreaterThanOrEqual(MIN_ITEM_SOFT_DELETES);

    const wrong = sites
      .filter((site) => {
        const implied = site.destroysKeyset ? 'unrestorable' : 'restorable';
        return REASON_DISPOSITION[site.reason] !== implied;
      })
      .map(
        (site) =>
          `${site.file} ${site.method}() ${site.destroysKeyset ? 'REPLACES the keyset' : 'leaves the keyset'} but retires rows as '${site.reason}'`,
      );
    expect(wrong).toEqual([]);

    // ANTI-VACUITY AT THE LEVEL OF THE SCAN, not just its total: both arms must
    // actually be exercised by a real route, or the check above is satisfied by
    // a corpus that only ever contains one kind of site.
    const destroying = sites.filter((s) => s.destroysKeyset);
    const preserving = sites.filter((s) => !s.destroysKeyset);
    expect(destroying.length).toBeGreaterThan(0);
    expect(preserving.length).toBeGreaterThan(0);

    // And the backfill-only value is written by no live path at all. A delete
    // route that started writing it would have stopped knowing what it was
    // doing, so its ABSENCE is asserted rather than assumed.
    expect(sites.map((s) => s.reason)).not.toContain('unknown_pre_m27');
  });
});
