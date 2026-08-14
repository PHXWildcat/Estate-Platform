/**
 * THE FENCE THAT MAKES `ENFORCED_GRANTS` A CLAIM RATHER THAN A COMMENT.
 *
 * `enforced-grants.ts` says which (resource, action) pairs some code path
 * actually honours, and `RolesService.addPermission` refuses everything else.
 * That is only worth anything while the table agrees with the enforcement —
 * and the defect it closes was precisely a table of promises with no
 * enforcement behind them, so a second copy of that mistake is the obvious way
 * to regress.
 *
 * Two directions, both derived from source rather than restated:
 *  1. Every declared pair is one the reader's SQL really filters on.
 *  2. Every file that touches `permission_grants` is a declared one — so a
 *     SECOND reader (which would enforce a pair nobody declared, the mirror of
 *     the original defect) cannot appear unremarked.
 *
 * The scans read comment-stripped source, carry anti-vacuity floors, and refuse
 * a SQL shape they cannot parse rather than silently matching nothing: a fence
 * that stops matching goes green, which is the failure this repo keeps finding
 * in its own fences (2026-08-07, 2026-08-10).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ENFORCED_GRANTS, isEnforcedGrant } from '../src/enforced-grants';

const SRC = join(__dirname, '..', 'src');

function source(file: string): string {
  return readFileSync(join(SRC, file), 'utf8');
}

/** Block and line comments removed, so prose can never satisfy a scan. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

/**
 * The SQL of profile's one grant reader, isolated from the rest of the file so
 * a literal elsewhere in `roles.repo.ts` cannot stand in for one in the query.
 */
function grantReaderSql(): string {
  const text = code(source('roles.repo.ts'));
  const start = text.indexOf('SELECT DISTINCT ra.scope_type');
  expect(start).toBeGreaterThan(-1);
  const end = text.indexOf('`', start);
  expect(end).toBeGreaterThan(start);
  return text.slice(start, end);
}

/**
 * The literals one column is compared against in the reader.
 *
 * Only the `col = 'literal'` form is understood, which is what the single
 * enforced pair can be written as. A second enforced pair CANNOT be expressed
 * that way — it needs an `IN`, or a tuple — so this throws rather than
 * returning a partial answer, and whoever adds that pair has to come here and
 * decide what the fence should say. That is the intended cost.
 */
function literalsComparedAgainst(sql: string, column: string): string[] {
  const mentions = [...sql.matchAll(new RegExp(`pg\\.${column}\\b([^\\n]*)`, 'g'))];
  const literals: string[] = [];
  for (const [, rest] of mentions) {
    const eq = /^\s*=\s*'([a-z][a-z0-9_.]*)'/.exec(rest ?? '');
    if (!eq) {
      throw new Error(
        `enforced-grants fence: the grant reader compares pg.${column} in a form ` +
          `this fence cannot read ("pg.${column}${rest ?? ''}"). Extend the fence in ` +
          `the same change — a scan that silently matches nothing passes.`,
      );
    }
    literals.push(eq[1] as string);
  }
  return literals;
}

describe('ENFORCED_GRANTS states what the reader actually honours', () => {
  it('declares exactly the (resource, action) pair the grant reader filters on', () => {
    const sql = grantReaderSql();
    const resources = literalsComparedAgainst(sql, 'resource');
    const actions = literalsComparedAgainst(sql, 'action');

    // The `=` form can only ever express one value per column, so the reader
    // honours exactly one pair. If that ever stops being true the extractor
    // above throws, and this expectation is where the new shape is reviewed.
    expect(resources).toHaveLength(1);
    expect(actions).toHaveLength(1);

    const honoured = [{ resource: resources[0] as string, action: actions[0] as string }];
    expect(ENFORCED_GRANTS.map((g) => ({ resource: g.resource, action: g.action }))).toEqual(
      honoured,
    );
  });

  it('carries a REASON per entry — which pairs exist is derivable, why is not', () => {
    expect(ENFORCED_GRANTS.length).toBeGreaterThan(0);
    for (const grant of ENFORCED_GRANTS) {
      expect(grant.because.length).toBeGreaterThan(40);
    }
  });

  it('refuses every pair the people surface used to offer and nothing honoured', () => {
    // The six combinations measured against real Postgres while scoping this:
    // one conferred access, five conferred nothing.
    expect(isEnforcedGrant('contact', 'read')).toBe(true);
    for (const [resource, action] of [
      ['contact', 'download'],
      ['asset', 'read'],
      ['asset', 'download'],
      ['document', 'read'],
      ['document', 'download'],
      // The old schema regex admitted any lowercase token at all.
      ['anything_at_all', 'read'],
    ] as const) {
      expect(isEnforcedGrant(resource, action)).toBe(false);
    }
  });
});

describe('nothing reads permission grants except the declared reader', () => {
  /**
   * Files allowed to name the table, and why. A NEW entry here is a claim that
   * something else now depends on grants — which is exactly when
   * `ENFORCED_GRANTS` may have gone stale, so the list is the prompt to check.
   */
  const TOUCHES_GRANTS: ReadonlyArray<{ file: string; because: string }> = [
    {
      file: 'roles.repo.ts',
      because: 'the ONE reader (effectiveContactReadGrants), plus the insert and revoke statements',
    },
    {
      file: 'contacts.service.ts',
      because: 'resolves the grantee set it hands the Cedar PEP — the only consumer of the reader',
    },
    {
      file: 'roles.service.ts',
      because: 'the write path, and where an unenforced pair is refused',
    },
    { file: 'app.module.ts', because: 'DI wiring for PermissionGrantsRepo, no grant logic' },
  ];

  it('is exactly the declared set, in both directions', () => {
    // Derived from the directory, never a hand-kept list: a list maintained by
    // memory beside a thing that grows is this repo's own recurring drift class.
    const files = readdirSync(SRC)
      .filter((f) => f.endsWith('.ts'))
      // The declaration itself is the subject of this fence, not a consumer of
      // grants — and `code()` strips comments but not STRINGS, so its own
      // `because` prose would otherwise satisfy the scan. Prose matching a scan
      // written to find code is how a fence starts measuring nothing.
      .filter((f) => f !== 'enforced-grants.ts');
    const found = files.filter((file) =>
      /permission_grants|effectiveContactReadGrants|PermissionGrantsRepo/.test(code(source(file))),
    );

    // Anti-vacuity: the listing must really have been walked, and the scan must
    // really have matched. A zero-length result here would make the equality
    // below trivially satisfiable by an empty declaration.
    expect(files.length).toBeGreaterThan(15);
    expect(found.length).toBeGreaterThan(2);

    expect(found.sort()).toEqual(TOUCHES_GRANTS.map((t) => t.file).sort());
    for (const entry of TOUCHES_GRANTS) {
      expect(entry.because.length).toBeGreaterThan(20);
    }
  });
});
