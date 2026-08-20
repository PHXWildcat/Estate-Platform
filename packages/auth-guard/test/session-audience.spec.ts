/**
 * THE SESSION-AUDIENCE FENCE (M15).
 *
 * `CallerGuard` enforces "this service admits these audiences". It cannot say
 * which services SHOULD, and that is the security property — the whole point of
 * the audience is that a leaked vault handoff reaches the vault service and
 * nothing else, which is false the moment a second service quietly binds
 * `ALLOWED_SESSION_AUDIENCES`. So the table in `session.ts` is checked against
 * the source rather than believed, in BOTH directions.
 *
 * The mechanism is `credential-graph.spec.ts`'s, for its reason: every service
 * depends on this package, so a suite here can never import services back
 * (workspace cycle). `readFileSync` creates no package edge — the
 * vault-crypto zero-dependency-fence precedent.
 *
 * Anchored on the DI TOKEN NAME, not on a service name or a comment, because a
 * binding is the only thing that actually widens the guard.
 *
 * THIS FILE IS THE SPEC `004_session_audience_and_handoffs.sql` PROMISES —
 * "a spec reads this file to pin the first to the second" — and it names
 * `@estate/auth-guard` as where `SESSION_AUDIENCES` lives. That was the
 * definition site when 004 was written; M16 PR1 moved the vocabulary to
 * `@estate/contracts` so the BFF could label sessions without depending on a
 * NestJS guard package, and auth-guard re-exports it (`src/session.ts`), which
 * is why the citation still resolves and why the import below reads
 * `../src/session`. The migration is deliberately NOT corrected: the migrator
 * checksums every applied file and raises `MigrationDriftError` on a mismatch,
 * so a comment edit blocks the next migration on every database that has run
 * it. A migration records what was true when it ran; the live fact lives here.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  AUDIENCE_ADMITTERS,
  AUDIENCE_ROUTE_ADMITTERS,
  DEFAULT_SESSION_AUDIENCE,
  SESSION_AUDIENCES,
} from '../src/session';

const SERVICES_DIR = join(__dirname, '..', '..', '..', 'apps', 'services');
const IDENTITY_MIGRATIONS = join(SERVICES_DIR, 'identity', 'migrations');
const TOKEN = 'ALLOWED_SESSION_AUDIENCES';

function serviceNames(): string[] {
  return readdirSync(SERVICES_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => existsSync(join(SERVICES_DIR, name, 'src', 'config.ts')))
    .sort();
}

/** Every .ts file under a service's src/, recursively. */
function sourceFiles(service: string): string[] {
  const root = join(SERVICES_DIR, service, 'src');
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.name.endsWith('.ts')) out.push(path);
    }
  };
  walk(root);
  return out;
}

/** Comments discuss the token by name; only a real `provide:` binding counts. */
function bindsToken(service: string): boolean {
  return sourceFiles(service).some((file) =>
    new RegExp(`provide:\\s*${TOKEN}\\b`).test(readFileSync(file, 'utf8')),
  );
}

/** The audience list a service binds, read out of its `useValue`. */
function boundAudiences(service: string): string[] {
  for (const file of sourceFiles(service)) {
    const match = new RegExp(`provide:\\s*${TOKEN}\\s*,\\s*useValue:\\s*\\[([^\\]]*)\\]`, 's').exec(
      readFileSync(file, 'utf8'),
    );
    if (match) {
      return [...(match[1] ?? '').matchAll(/'([^']+)'/g)].map((m) => m[1] ?? '').sort();
    }
  }
  return [];
}

describe('session-audience grants match the declaration', () => {
  const services = serviceNames();

  it('finds the services it is meant to be checking', () => {
    // Guards against the scan silently matching nothing and passing vacuously
    // — the failure mode the credential-graph anti-drop check was caught in.
    expect(services.length).toBeGreaterThan(5);
    expect(services).toContain('vault');
  });

  it('declares admitters only for real, non-default audiences', () => {
    for (const audience of Object.keys(AUDIENCE_ADMITTERS)) {
      expect(SESSION_AUDIENCES).toContain(audience);
      expect(audience).not.toBe('account');
    }
  });

  it('every declared admitter actually binds the token', () => {
    for (const [audience, admitters] of Object.entries(AUDIENCE_ADMITTERS)) {
      for (const service of admitters) {
        expect(services).toContain(service);
        expect(boundAudiences(service)).toContain(audience);
      }
    }
  });

  it('NO UNDECLARED SERVICE binds the token', () => {
    const declared = new Set(Object.values(AUDIENCE_ADMITTERS).flat());
    for (const service of services) {
      if (declared.has(service)) continue;
      expect({ service, binds: bindsToken(service) }).toEqual({ service, binds: false });
    }
  });

  it('an admitter binds no audience beyond what it is granted, plus account', () => {
    // The reverse direction: vault may not quietly widen its own useValue to a
    // third audience while the table still reads `{ vault: ['vault'] }`.
    for (const service of new Set(Object.values(AUDIENCE_ADMITTERS).flat())) {
      const granted = Object.entries(AUDIENCE_ADMITTERS)
        .filter(([, admitters]) => admitters.includes(service))
        .map(([audience]) => audience);
      expect(boundAudiences(service).sort()).toEqual(['account', ...granted].sort());
    }
  });

  it('vault is the only service admitting the vault audience', () => {
    // Stated explicitly as well as derived: this one sentence is the milestone's
    // claim, and a table edit that broke it should fail a test that NAMES it.
    expect(AUDIENCE_ADMITTERS.vault).toEqual(['vault']);
  });

  /**
   * THE ROUTE-LEVEL HALF (M15 PR3).
   *
   * A service that binds nothing service-wide can still open ONE route to
   * another audience with `@AllowSessionAudiences`. That is a narrower grant
   * than the table above, and narrower grants are the ones that get added
   * quietly — so both directions are checked: every declared entry names a
   * handler that really carries the decorator, and NO undeclared handler
   * anywhere carries it.
   */
  describe('route-level widenings', () => {
    /**
     * Every `@AllowSessionAudiences(...)` in a service, as `service:handler`.
     *
     * Line-oriented rather than one big regex: a `[\\s\\S]{0,N}` bridge between
     * the decorator and the handler backtracks past `async` and lands on
     * whatever comes next, which is how the first version of this scan
     * reported `identity:constructor`. A fence that matches the wrong thing is
     * worse than one that matches nothing, because it still goes green.
     */
    /**
     * A SECOND, DELIBERATELY DUMBER READING of the same source.
     *
     * The scan above is LINE-oriented and its regex needs the closing paren on
     * the same line, so a decoration wrapped across lines was `continue`d —
     * INVISIBLE rather than refused, which is the one failure mode this file's
     * own header calls worse than matching nothing. The M21 PR4 review measured
     * it: a class-level
     *
     *     @AllowSessionAudiences(
     *       // console support
     *       'operator',
     *     )
     *
     * on `AuthController` left `prettier --check` green, identity's
     * session-audience, mint-paths and guards specs green (26 passed) and this
     * package's whole suite green (221 passed) — while the real `Reflector`
     * call that `SessionGuard` makes resolved `mintHandoff` to
     * `["account","operator"]`, i.e. an operator session could mint another
     * handoff and chain a leaked code forward, which is the invariant
     * `AUDIENCE_ROUTE_ADMITTERS` calls ABSENT AND LOAD-BEARING.
     *
     * PRETTIER IS WHY THE BARE WRAPPED FORM IS NOT THE RISK and a comment is:
     * `prettier --check` is a blocking gate and collapses a multi-line
     * decorator whose arguments fit in 100 columns, which they always do for
     * this vocabulary. A comment inside the parens keeps it multi-line and
     * prettier-stable — and this codebase comments everything, so that is the
     * house style rather than a contrivance.
     *
     * Counting is the right shape because it cannot be evaded by the thing it
     * is watching for: whatever form a decoration takes, it contains the
     * decorator's name exactly once. `settlement`'s own audience spec has had
     * this reconciliation since PR3b; the shared fence did not.
     */
    function countDecorations(source: string): number {
      // Comments discuss the decorator by name (the credential-graph habit),
      // so strip them before counting or the reconciliation is off by however
      // many times the prose mentions it.
      const withoutComments = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
      return (withoutComments.match(/@AllowSessionAudiences\b/g) ?? []).length;
    }

    let seenDecorations = 0;

    function decoratedRoutes(): Array<{ key: string; audiences: string[] }> {
      const found: Array<{ key: string; audiences: string[] }> = [];
      for (const service of services) {
        for (const file of sourceFiles(service)) {
          seenDecorations += countDecorations(readFileSync(file, 'utf8'));
          const lines = readFileSync(file, 'utf8').split('\n');
          for (const [index, line] of lines.entries()) {
            // Comments discuss the decorator by name — the credential-graph
            // habit. Only a real decoration counts.
            const trimmed = line.trim();
            if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) {
              continue;
            }
            const decorator = /@AllowSessionAudiences\(([^)]*)\)/.exec(line);
            if (!decorator) continue;
            const audiences = [...(decorator[1] ?? '').matchAll(/'([^']+)'/g)].map(
              (m) => m[1] ?? '',
            );
            // The handler is the first line after it that is not another
            // decorator and not blank.
            for (const next of lines.slice(index + 1)) {
              const text = next.trim();
              if (text === '' || text.startsWith('@') || text.startsWith('//')) continue;
              const handler = /^(?:public |private |protected )?(?:async )?(\w+)\s*\(/.exec(text);
              found.push({ key: `${service}:${handler?.[1] ?? '<unparsed>'}`, audiences });
              break;
            }
          }
        }
      }
      return found;
    }

    it('finds the decorated routes it is meant to be checking', () => {
      // Anti-vacuity: a regex that stops matching is worse than no fence at
      // all, which is the 2026-08-07 credential-graph lesson.
      seenDecorations = 0;
      const routes = decoratedRoutes();
      expect(routes.length).toBeGreaterThan(0);
      // PARSED === SEEN. A decoration the line-oriented scan cannot read must
      // fail loudly rather than be skipped: an unread decoration is a widening
      // nothing in this repository is looking at.
      expect({ parsed: routes.length, seen: seenDecorations }).toEqual({
        parsed: seenDecorations,
        seen: seenDecorations,
      });
      // And every one is ATTRIBUTED. A decorator the scan cannot tie to a
      // handler must fail loudly rather than be silently pinned to whatever
      // token followed it.
      expect(routes.filter((r) => r.key.endsWith(':<unparsed>'))).toEqual([]);
    });

    /**
     * THE SCAN ABOVE IS KEYED ON A NAME THE CALLER CHOOSES, and the M16 review
     * found that is the same shape the credential graph was fixed for twice
     * (2026-07-28: "a renamed secret evades a name-keyed fence"; 2026-08-07: "a
     * fence that stops matching is worse than one that never existed").
     *
     * `CallerGuard.audiencesFor` and identity's `SessionGuard` both resolve
     * `SESSION_AUDIENCE_METADATA` through `Reflector.getAllAndOverride`, so a
     * route is widened by CARRYING THAT KEY, however it acquired it — an
     * aliased import (`import { AllowSessionAudiences as Allow }`) or a raw
     * `@SetMetadata(SESSION_AUDIENCE_METADATA, [...])` is honoured at runtime
     * and matched by nothing above. Only `vault` and `identity` have a
     * second-layer spec that reads real handler metadata; for the other seven
     * services this scan is the whole enforcement.
     *
     * So the fence also asserts that the ONLY route to the metadata key is the
     * declared decorator. That cannot be evaded by renaming, because it is
     * keyed on the thing the guard actually reads.
     */
    it('the metadata key is written by the DECORATOR and by nothing else', () => {
      const offenders: string[] = [];
      for (const service of services) {
        for (const file of sourceFiles(service)) {
          for (const [index, line] of readFileSync(file, 'utf8').split('\n').entries()) {
            const trimmed = line.trim();
            if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) {
              continue;
            }
            // A service may IMPORT the key (its own guard wiring does), but it
            // may not hand it to SetMetadata: that is a decoration this scan
            // cannot see.
            if (/SetMetadata\s*\(\s*SESSION_AUDIENCE_METADATA/.test(trimmed)) {
              offenders.push(`${service}:${file}:${String(index + 1)} raw SetMetadata`);
            }
            // An alias renames the decorator out of the scan's sight.
            const aliased = /\bAllowSessionAudiences\s+as\s+(\w+)/.exec(trimmed);
            if (aliased) {
              offenders.push(
                `${service}:${file}:${String(index + 1)} aliased as ${aliased[1] ?? ''}`,
              );
            }
          }
        }
      }
      expect(offenders).toEqual([]);
    });

    it('every declared route really carries the decorator, for that audience', () => {
      const decorated = new Map(decoratedRoutes().map((r) => [r.key, r.audiences]));
      for (const [audience, keys] of Object.entries(AUDIENCE_ROUTE_ADMITTERS)) {
        for (const key of keys) {
          expect({ key, found: decorated.has(key) }).toEqual({ key, found: true });
          expect(decorated.get(key)).toContain(audience);
        }
      }
    });

    it('NO UNDECLARED ROUTE carries it', () => {
      const declared = new Set(Object.values(AUDIENCE_ROUTE_ADMITTERS).flat());
      for (const route of decoratedRoutes()) {
        expect({ route: route.key, declared: declared.has(route.key) }).toEqual({
          route: route.key,
          declared: true,
        });
      }
    });

    it('a route-level widening names an audience the route’s service does NOT hold', () => {
      // Otherwise the decorator is decoration: the service-wide grant already
      // admits it, and someone reading the route would believe a narrower
      // grant is in force than actually is.
      for (const [audience, keys] of Object.entries(AUDIENCE_ROUTE_ADMITTERS)) {
        for (const key of keys) {
          const service = key.split(':')[0] as string;
          expect({ key, serviceWide: boundAudiences(service).includes(audience) }).toEqual({
            key,
            serviceWide: false,
          });
        }
      }
    });
  });

  /**
   * NO AUDIENCE IS DECLARED WITH NOBODY TO HOLD IT (M16).
   *
   * Both tables are `Record`s over the non-default audiences, so widening the
   * union is a compile error until each is filled in — which is the fence
   * working. But an EMPTY ARRAY satisfies the type, and every assertion above
   * iterates the arrays, so a declaration of `{ …, extension: [] }` makes the
   * whole suite pass over an audience nothing admits.
   *
   * That is not a tidiness point. An audience with no admitter anywhere is a
   * session identity can mint and no service will ever accept — a credential
   * that fails closed everywhere while reading, from the table, like a granted
   * capability. The M8 rule about a zero-holder credential edge applies: it may
   * exist, but only as a DELIBERATE subtraction somebody wrote down, never as
   * the default an empty literal hands you.
   */
  it('every declared audience is admitted by at least one service or route', () => {
    for (const audience of SESSION_AUDIENCES) {
      if (audience === DEFAULT_SESSION_AUDIENCE) continue;
      const serviceWide = AUDIENCE_ADMITTERS[audience] ?? [];
      const perRoute = AUDIENCE_ROUTE_ADMITTERS[audience] ?? [];
      expect({ audience, admitted: serviceWide.length + perRoute.length > 0 }).toEqual({
        audience,
        admitted: true,
      });
    }
  });
});

/**
 * THE VOCABULARY IS CLOSED IN SQL AS WELL AS IN TYPESCRIPT (M16).
 *
 * `004_session_audience_and_handoffs.sql` states that the audience vocabulary is
 * closed in three places — this CHECK, the `SESSION_AUDIENCES` union, and the
 * zod enum on the introspection response — and that "a spec reads this file to
 * pin the first to the second".
 *
 * NO SUCH SPEC EXISTED. A grep of the repo for the migration's name returns
 * nothing; the suite above imports `SESSION_AUDIENCES` and scans SERVICE SOURCE,
 * never a `.sql` file. The claim was false for the life of M15 — worse than the
 * 2026-08-07 lesson, where a fence stopped matching, because this one never
 * matched while a migration cited it. This is that spec.
 *
 * The third place needs no pinning and is deliberately not checked here: the
 * introspection enum is `z.enum(SESSION_AUDIENCES)` in `verifier.ts`, DERIVED
 * from the union rather than restating it, so it cannot drift by construction.
 * Only the SQL is a second hand-written copy.
 *
 * IT FOLLOWS THE MIGRATION CHAIN RATHER THAN ONE FILE, which is the whole reason
 * this is not three lines. Migrations are append-only under checksum drift
 * detection, so widening the vocabulary means a LATER migration dropping and
 * re-adding the constraint — a fence pinned to 004's text would go red on the
 * first legitimate widening and be deleted by whoever hit it. What is checked is
 * the EFFECTIVE constraint: the last statement, in filename order, that
 * constrains that table's `audience` column.
 */
describe('the SQL audience vocabulary matches the TypeScript union', () => {
  /**
   * One statement's contribution to the audience column's shape.
   *
   * `values` and `defaultValue` are OPTIONAL and tracked separately, because
   * they are independent properties with independent histories — which this
   * suite learned the hard way. M16's widening migration is
   * `ALTER TABLE … DROP CONSTRAINT` + `ADD CONSTRAINT`, touching the CHECK and
   * saying nothing about the DEFAULT; a first draft took "the last statement
   * mentioning audience" as authoritative for both and duly reported that the
   * column had lost its default. Collapsing two facts into one lookup is the
   * same shape as the mistakes this file exists to catch.
   */
  interface AudienceConstraint {
    readonly file: string;
    readonly table: string;
    /** Present when this statement (re)defines the CHECK. */
    readonly values?: string[];
    /** Present when this statement decides the DEFAULT; null means DROP DEFAULT. */
    readonly defaultValue?: string | null;
    /**
     * True when the statement carries a CHECK that MENTIONS `audience` in a
     * form this parser could not read. See `refuses an audience CHECK it
     * cannot parse` below — this is the difference between a fence that fails
     * and a fence that goes quietly blind.
     */
    readonly unparseableCheck?: true;
  }

  /**
   * A CHECK clause that constrains `audience` AT ALL, in any syntax.
   *
   * Deliberately broader than the parser below it. `CHECK (audience = 'x')`
   * and `CHECK (audience IN ('x'))` mean the same thing to Postgres and only
   * the second is readable here, so without this detector a migration written
   * the first way would be INVISIBLE: `effectiveCheck` would return the
   * previous constraint and every assertion in this file would silently
   * measure the wrong statement. That is not hypothetical — `docs/04` and the
   * decision log both misquote the shipped `auth_handoffs` DDL as
   * `CHECK (audience = 'vault')`, so somebody "correcting" the SQL to match
   * the prose is the likeliest way this fence ever goes blind.
   */
  const AUDIENCE_CHECK_ANY = /CHECK\s*\(\s*[^)]*\baudience\b/i;

  /**
   * Every audience CHECK in identity's migrations, in application order.
   *
   * `$$…$$` bodies and `--` comments are stripped BEFORE splitting on `;`,
   * because 001 defines trigger functions whose bodies contain semicolons and a
   * naive split would attribute half a function body to the wrong table.
   */
  function audienceConstraints(): AudienceConstraint[] {
    const files = readdirSync(IDENTITY_MIGRATIONS)
      .filter((name) => name.endsWith('.sql'))
      .sort();
    const found: AudienceConstraint[] = [];
    for (const file of files) {
      const sql = readFileSync(join(IDENTITY_MIGRATIONS, file), 'utf8')
        .replace(/\$\$[\s\S]*?\$\$/g, ' ')
        .replace(/--[^\n]*/g, ' ');
      for (const statement of sql.split(';')) {
        const check = /CHECK\s*\(\s*audience\s+IN\s*\(([^)]*)\)\s*\)/i.exec(statement);
        const setsDefault = /audience[^;]*?DEFAULT\s+'([^']+)'/i.exec(statement);
        const dropsDefault = /ALTER\s+COLUMN\s+audience\s+DROP\s+DEFAULT/i.test(statement);
        // A CHECK that constrains `audience` in a shape the reader above
        // cannot parse is RECORDED rather than skipped, so the assertion that
        // names the property can fail on it.
        const unreadableCheck = !check && AUDIENCE_CHECK_ANY.test(statement);
        if (!check && !setsDefault && !dropsDefault && !unreadableCheck) continue;
        const target =
          /(?:ALTER|CREATE)\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)/i.exec(statement);
        found.push({
          file,
          table: (target?.[1] ?? '<unparsed>').toLowerCase(),
          ...(check
            ? { values: [...(check[1] ?? '').matchAll(/'([^']+)'/g)].map((m) => m[1] ?? '').sort() }
            : {}),
          ...(dropsDefault
            ? { defaultValue: null }
            : setsDefault
              ? { defaultValue: setsDefault[1] as string }
              : {}),
          ...(unreadableCheck ? { unparseableCheck: true as const } : {}),
        });
      }
    }
    return found;
  }

  /** The CHECK actually in force for a table: the last statement to define one. */
  function effectiveCheck(table: string): string[] | undefined {
    return audienceConstraints()
      .filter((c) => c.table === table && c.values !== undefined)
      .at(-1)?.values;
  }

  /** The DEFAULT in force: the last statement to decide one. `null` = dropped. */
  function effectiveDefault(table: string): string | null | undefined {
    return audienceConstraints()
      .filter((c) => c.table === table && c.defaultValue !== undefined)
      .at(-1)?.defaultValue;
  }

  it('finds the constraints it is meant to be checking', () => {
    // Anti-vacuity, the credential-graph lesson: a scan that silently matches
    // nothing passes every assertion below it.
    const all = audienceConstraints();
    expect(all.length).toBeGreaterThan(0);
    expect(all.filter((c) => c.table === '<unparsed>')).toEqual([]);
    expect(all.map((c) => c.table)).toContain('sessions');
    expect(all.map((c) => c.table)).toContain('auth_handoffs');
  });

  it('REFUSES an audience CHECK it cannot parse, rather than reading past it', () => {
    /*
     * THE DIFFERENCE BETWEEN A FENCE THAT FAILS AND ONE THAT GOES BLIND.
     *
     * Every assertion below reads `effectiveCheck`, which is "the LAST
     * statement to define a CHECK" — so a statement this parser cannot read is
     * not merely unmeasured, it hands the assertions an OLDER constraint and
     * they pass against a database that no longer matches. `CHECK (audience =
     * 'x')` is exactly that shape, is valid SQL, means the same thing to
     * Postgres, and is how both `docs/04` and the decision log misquote the
     * shipped `auth_handoffs` DDL — so the likeliest route to blindness here is
     * somebody making the SQL agree with the prose.
     *
     * The M21 PR1 rule, restated for a second parser: a scan that meets a shape
     * it does not understand must say so. This is what lets every other test in
     * this describe be trusted, and it is why M21 PR3's operator migration must
     * be written in the `IN (...)` form or turn this red.
     */
    const unparseable = audienceConstraints().filter((c) => c.unparseableCheck);
    expect(unparseable.map((c) => `${c.file}: audience CHECK in an unreadable form`)).toEqual([]);
  });

  it('sessions.audience admits EXACTLY the declared union', () => {
    // Both directions in one assertion. A value in the union and not the CHECK
    // means identity cannot mint what its own types say exists — a runtime
    // 23514 on the first session of that kind. A value in the CHECK and not the
    // union means the database accepts an audience `CallerGuard` has never
    // heard of, which the verifier's enum then fails closed on: an outage
    // shaped like a bug rather than a control.
    expect(effectiveCheck('sessions')).toEqual([...SESSION_AUDIENCES].sort());
  });

  it('sessions.audience defaults to the same value the TypeScript default names', () => {
    // The column default exists so M15's ALTER could populate pre-existing
    // rows, and `DEFAULT_SESSION_AUDIENCE` is what an absent field parses to.
    // Two statements of one fact, which must not drift.
    expect(effectiveDefault('sessions')).toBe(DEFAULT_SESSION_AUDIENCE);
  });

  it('a handoff can never mint the DEFAULT audience', () => {
    // THE RISK MOVED TWICE AND THE CHECK STAYED PUT, which is why this comment
    // is a history rather than a description. M15 typed `mint`'s `audience`
    // PARAMETER as the full union, so `mint(user, session, 'account')`
    // type-checked and this CHECK was all that stopped it. M16 deleted the
    // parameter — a knob nobody turns is one a later milestone finds and
    // assumes the database agrees with — leaving `const HANDOFF_AUDIENCE:
    // SessionAudience`, annotated with the same full union, so reassigning it
    // was the same hazard in a new place. M21 PR3a brought the parameter back
    // (the operator origin needs it) but typed it as `HANDOFF_AUDIENCES`, so
    // `'account'` no longer type-checks at all and the compiler refuses it
    // before the database ever sees it. This CHECK is now the second line
    // rather than the only one — and it is still asserted, because a type is a
    // claim about source and this is a claim about the column.
    const handoffs = effectiveCheck('auth_handoffs');
    expect(handoffs?.length).toBeGreaterThan(0);
    expect(handoffs).not.toContain(DEFAULT_SESSION_AUDIENCE);
    for (const value of handoffs ?? []) {
      expect(SESSION_AUDIENCES).toContain(value);
    }
  });

  it('the handoff audiences TypeScript will mint are exactly the ones the column admits', () => {
    /*
     * "ASSUMING THE DATABASE AGREES" IS NOW CHECKED RATHER THAN HOPED.
     *
     * M16 deleted `mint`'s audience parameter and wrote the condition for its
     * return: a future audience "adds the parameter back in the same change as
     * the DDL widening — which is strictly better than finding the parameter
     * already there and assuming the database agrees." M21 PR3a is that change,
     * and this is the assertion that makes the second half true.
     *
     * TWO HAND-WRITTEN LISTS, one in TypeScript and one in SQL, are the drift
     * class this repo has recorded more times than any other. Widen the CHECK
     * and forget the union: an operator handoff is refused by the compiler, and
     * the route simply cannot be written. Widen the union and forget the CHECK:
     * every mint of the new audience dies on a 23514 at runtime, on a ceremony
     * whose failures are deliberately indistinguishable from each other, so it
     * would surface as `invalid_code` — the one answer that explains nothing.
     *
     * Read by `readFileSync` from the service's source rather than imported,
     * for `credential-graph.spec.ts`'s reason: every service depends on this
     * package, so a spec here can never import one back.
     */
    const source = readFileSync(
      join(SERVICES_DIR, 'identity', 'src', 'handoff.service.ts'),
      'utf8',
    );
    const declared = /export const HANDOFF_AUDIENCES = \[([^\]]*)\] as const;/.exec(source);
    // Anti-vacuity: a renamed or reshaped constant must fail loudly here rather
    // than leave the comparison below matching two empty sets.
    expect({ found: declared !== null }).toEqual({ found: true });
    const audiences = [...(declared?.[1] ?? '').matchAll(/'([a-z]+)'/g)].map((m) => m[1]);
    expect(audiences.length).toBeGreaterThan(0);

    expect(audiences.slice().sort()).toEqual(
      (effectiveCheck('auth_handoffs') ?? []).slice().sort(),
    );
  });
});
