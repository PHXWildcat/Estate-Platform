/**
 * NO RUNTIME SESSION MAY MINT AN OPERATOR.
 *
 * WHY THIS EXISTS. `settlement_operators` decides who may run docs/03 §5.1's
 * mandatory human review — approve a death case, lock an account, approve a
 * distribution. The whole safety argument for an allowlist standing in for the
 * TB7 operator platform is that a compromised operator session can act as the
 * operator it already is and cannot create another. Until M21 PR1 that
 * property was asserted in three docstrings and checked nowhere, and one of
 * those docstrings was wrong about its own mechanism: `operators.repo.ts` said
 * its write methods were "the CLI-only write path" while `operator-cli.ts`
 * reimplemented both in raw SQL and called neither.
 *
 * WHAT IT ASSERTS, in both directions:
 *
 *   1. Only `operator-cli.ts` calls the write methods. A controller or service
 *      that reached them would be a runtime path to minting an operator, which
 *      is the exact thing forbidden.
 *   2. Only `operator-cli.ts` writes the table in raw SQL. Routing the check
 *      through the repo's method names alone would be evadable by the very
 *      thing that was wrong before — an inline `INSERT INTO
 *      settlement_operators`.
 *   3. The CLI really does call them. Without this the fence passes vacuously
 *      the day somebody reverts the CLI to raw SQL, which is the state this PR
 *      found the repo in.
 *
 * WHY A SOURCE SCAN. The repo's rule is to anchor a fence on what the consumer
 * actually reads, and there is no runtime seam here to hang a guard on: the
 * CLI and the service share one class by design, so the difference between a
 * sanctioned and an unsanctioned call is WHERE IT IS WRITTEN. That is a fact
 * about the source, so the source is what gets scanned — the vault-crypto
 * zero-dependency-fence precedent, which creates no package edge.
 *
 * SCOPE, stated so it is not over-read: this bounds the settlement service's
 * own source. It does not and cannot stop somebody holding the database from
 * writing the row by hand — see the CLI's own docstring on why `--by` is
 * attribution rather than authentication.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, sep } from 'node:path';

const SRC = join(__dirname, '..', 'src');

/** The one file allowed to write the allowlist. */
const CEREMONY = 'operator-cli.ts';

/** Repo methods that WRITE the allowlist. `isOperator`/`listActive` read. */
const WRITE_METHODS = ['grant', 'revoke'] as const;

/** Source with comments and string literals removed, so a mention is a call. */
function code(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1 ')
    .replace(/`(?:\\[\s\S]|[^\\`])*`/g, '``')
    .replace(/'(?:\\.|[^\\'])*'/g, "''")
    .replace(/"(?:\\.|[^\\"])*"/g, '""');
}

/**
 * Every .ts file under src/, RECURSIVELY, as { file, code }.
 *
 * The directory is flat today and the walk is deliberately not: docs/03 §6y
 * assigns M21 the lesson that a fence whose input is narrower than its claim
 * goes green for the same reason it is wrong, and a non-recursive read would
 * stop covering this service the day somebody adds `src/operators/`. That is
 * the whole defect, arriving by a directory rename rather than by an edit.
 */
function walk(dir: string, prefix = ''): Array<{ file: string; text: string }> {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) return walk(join(dir, entry.name), rel);
    return entry.name.endsWith('.ts')
      ? [{ file: rel, text: readFileSync(join(dir, entry.name), 'utf8') }]
      : [];
  });
}

/** Raw text, for scans that must see inside template literals (the SQL). */
function rawSources(): Array<{ file: string; text: string }> {
  return walk(SRC);
}

/** Comment- and literal-stripped, so a mention is a call. */
function sources(): Array<{ file: string; text: string }> {
  return rawSources().map(({ file, text }) => ({ file, text: code(text) }));
}

describe('the operator allowlist has exactly one write path', () => {
  const files = sources();

  it('scans a real corpus, and the whole of it (anti-vacuity)', () => {
    // Two regexes that quietly match nothing agree perfectly.
    expect(files.length).toBeGreaterThanOrEqual(20);
    expect(files.map((f) => f.file)).toContain(CEREMONY);
    expect(files.map((f) => f.file)).toContain('operators.repo.ts');

    // The corpus equals the PLATFORM's own recursive read, which is an oracle
    // this file did not write. The tree is flat today, so a non-recursive walk
    // would pass every other assertion here; this is the one that turns red the
    // moment somebody adds `src/operators/` and the walk stops covering the
    // service it claims to cover.
    const truth = readdirSync(SRC, { recursive: true, encoding: 'utf8' })
      .filter((f) => f.endsWith('.ts'))
      .map((f) => f.split(sep).join('/'))
      .sort();
    expect(files.map((f) => f.file).sort()).toEqual(truth);
  });

  it.each(WRITE_METHODS)('only the ceremony calls OperatorsRepo.%s', (method) => {
    // `operators.grant(...)` / `this.operators.revoke(...)`, on the property
    // name the service and the CLI both bind the repo to. The declaration in
    // operators.repo.ts is `async grant(` and does not match.
    const call = new RegExp(`\\boperators\\s*\\.\\s*${method}\\s*\\(`);
    const callers = files.filter((f) => call.test(f.text)).map((f) => f.file);
    expect(callers).toEqual([CEREMONY]);
  });

  it.each(WRITE_METHODS)(
    'the ceremony really does call %s (the fence is not vacuous)',
    (method) => {
      // Without this the two assertions above are satisfied by a CLI that calls
      // NEITHER — which is precisely the state M21 PR1 found: the repo's write
      // methods had no caller anywhere and the CLI wrote raw SQL.
      const ceremony = files.find((f) => f.file === CEREMONY);
      expect(ceremony).toBeDefined();
      expect(
        new RegExp(`\\boperators\\s*\\.\\s*${method}\\s*\\(`).test(
          (ceremony as { text: string }).text,
        ),
      ).toBe(true);
    },
  );

  it('only operators.repo.ts writes the table in SQL', () => {
    // The method-name scan alone is evadable by an inline statement, which is
    // how the previous CLI worked. Reads (`SELECT`) are unrestricted; writes
    // must go through the repo, which the assertions above then bound to the
    // ceremony.
    // Read RAW, not through `code()`: the SQL lives inside template literals,
    // which `code()` blanks, so a comment-stripped scan would find nothing at
    // all and pass vacuously.
    const write = /\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+settlement_operators\b/i;
    const raw = rawSources()
      .filter(({ text }) => write.test(text))
      .map(({ file }) => file)
      .sort();
    expect(raw).toEqual(['operators.repo.ts']);
  });

  it('no controller reaches the allowlist at all', () => {
    // Defence in depth against the shape the rule exists to forbid: a route
    // handler is where a runtime session would arrive.
    const controllers = files.filter((f) => f.file.endsWith('.controller.ts'));
    expect(controllers.length).toBeGreaterThanOrEqual(3);
    for (const c of controllers) {
      expect(c.text).not.toMatch(/settlement_operators|OperatorsRepo/);
    }
  });
});
