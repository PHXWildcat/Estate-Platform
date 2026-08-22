/**
 * THE ERASURE BOUNDARY: WHICH SERVICES A CRYPTO-SHRED MUST REACH, DERIVED.
 *
 * WHY THIS EXISTS. docs/04's queue annotates M25 "must precede any new
 * encrypted data class". That sentence has no mechanism behind it: nothing
 * fails when a tenth service arrives holding ciphertext, and the erasure that
 * was supposed to cover it is a paragraph. The set of domains an erasure has to
 * reach is exactly the kind of list this repo keeps getting wrong by hand — it
 * grew from one service to eight across nineteen milestones, one KEK at a time,
 * and no file anywhere states it.
 *
 * WHAT IT ASSERTS, and the shape is a CROSS-CHECK rather than a list. The
 * participant set is derived TWICE, from sources that know nothing about each
 * other, and the two must agree as SETS:
 *
 *   A. `apps/stack/src/topology.ts` — every `SERVICES` entry whose `kekAlias`
 *      is non-null. That field is what the stack generator turns into a KMS key
 *      id, so it is what the RUNTIME reads, not a name someone chose.
 *   B. `apps/services/<name>/migrations/*.sql` — every service that creates a
 *      table whose name ends in `deks`. Eight services, and they do NOT agree
 *      on the table name: `deks` in three, `settlement_deks`, `document_deks`,
 *      `notification_deks`, `plaid_deks` and `assistant_deks` in the rest. That
 *      disagreement is what makes B an independent derivation instead of a
 *      restatement of A — a fence keyed on one spelling would have found three.
 *
 * Comparing SETS and not counts is the M23 rule: mis-attribution preserves
 * counts. A service that gains a KEK while another loses its DEK table keeps
 * the total at eight and is exactly the change this must catch.
 *
 * C. The third leg is the storage primitive: every participant's
 *    `dek.repository.ts` must implement `markDestroyed`, the method
 *    `FieldCrypto.destroyDek` calls. A domain with a KEK and no way to record
 *    the destruction cannot be erased, and today all eight have it — which is
 *    the point. The machinery is built; only the caller is missing.
 *
 * WHY vault AND audit ARE EXCLUDED, asserted rather than assumed. Both carry
 * `kekAlias: null` and neither creates a DEK table, so they fall out of A and B
 * on their own — but a null that starts meaning something else would silently
 * shrink the participant set, so the exclusion is named here with its reason.
 * Vault is Zone A: the server can decrypt nothing, and its erasure primitive is
 * `POST /v1/vault/reset`, which already destroys the keyset, the emergency
 * escrow and the recovery keypair. Audit holds entity ids and enums, never
 * ciphertext, and is append-only by design.
 *
 * D. THE CALLER ALLOWLIST, which is this fence's other half and the reason it
 *    lands in PR0 rather than with the driver. docs/02 §conventions and
 *    `packages/crypto/src/dek.ts` both say crypto-shredding is performed by "a
 *    privileged retention job (not the app role)". There is no such role: the
 *    repo has no `CREATE ROLE` or `GRANT` outside test files, and M25 ships
 *    owner-initiated erasure without one (docs/06, 2026-08-21). So the
 *    privilege boundary those comments describe is replaced by a declared set
 *    of components permitted to call `destroyDek`, and everything else is
 *    refused here.
 *
 *    STATED PLAINLY BECAUSE IT MATTERS: this is WEAKER than a database role and
 *    covers a different threat. A role stops a compromised app process from
 *    destroying keys at runtime; this stops a developer from adding a second
 *    caller in review. The runtime direction is a residual, recorded in
 *    docs/03 §6kk, and nobody should read this fence as closing it.
 *
 *    THE SET IS NO LONGER EMPTY. M25 PR3 added identity's erasure service as
 *    the first production caller, in the same change as the call, and that is
 *    what turned this leg from a claim about a vacuum into a real allowlist:
 *    until PR3 an assertion that "nothing undeclared calls destroyDek" was true
 *    of a repo where nothing called it at all.
 *
 * E. THE PROGRESS VOCABULARY, added in PR3. `erasure_domain_progress.domain`
 *    is a literal CHECK — Postgres cannot constrain against another project's
 *    source — and `ERASURE_DOMAINS` in `packages/contracts/src/erasure.ts` is
 *    the TypeScript the driver seeds rows from. Both are compared against A as
 *    SETS, so a ninth KEK-holding service turns this red in both places until
 *    it is named, and a domain named in one and not the other cannot ship.
 *    Three spellings of one list, pinned to the thing the runtime reads.
 *
 * ANTI-VACUITY, because a scanner that sees nothing and a tree that contains
 * nothing look identical — and leg D asserts an ABSENCE, which is the shape
 * that fails green. `the caller scan can see a call at all` is the positive
 * control: it points the same walker at the one call site that DOES exist,
 * `packages/crypto/test/envelope.spec.ts`, and demands it be found. If that
 * assertion ever goes red the emptiness above means nothing.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import * as ts from 'typescript';
import { ERASURE_DOMAINS } from '../src/erasure';

const REPO_ROOT = join(__dirname, '..', '..', '..');
const TOPOLOGY = join(REPO_ROOT, 'apps', 'stack', 'src', 'topology.ts');
const SERVICES_DIR = join(REPO_ROOT, 'apps', 'services');

/**
 * Floor for the participant set. Set BELOW the eight measured at M25 PR0 so
 * ordinary work does not trip it, and high enough that a parser which stops
 * matching cannot pass — the 2026-08-07 lesson, that two regexes matching
 * nothing agree perfectly.
 */
const MIN_DOMAINS = 8;

/**
 * Components permitted to call `FieldCrypto.destroyDek`, as repo-relative path
 * prefixes. Grown here in the same change as the call it permits — the
 * route↔consumer discipline applied to the most irreversible verb in the
 * product.
 *
 * ONE ENTRY, AND IT IS A FILE RATHER THAN A DIRECTORY. `apps/services/identity`
 * would permit every future file in the service, which is the widening that
 * costs nothing to write and everything to notice.
 */
const ERASURE_COMPONENTS: readonly string[] = [
  join('apps', 'services', 'identity', 'src', 'erasure.service.ts'),
];

/** The DDL that carries the progress ledger's domain vocabulary. */
const PROGRESS_DDL = join(
  REPO_ROOT,
  'apps',
  'services',
  'identity',
  'migrations',
  '015_erasure_execution.sql',
);

/** The one call site that exists today, and the positive control for leg D. */
const KNOWN_TEST_CALLER = join('packages', 'crypto', 'test', 'envelope.spec.ts');

function parse(file: string): ts.SourceFile {
  return ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
}

/** Every `.ts` file under a directory, skipping build output and dependencies. */
function tsFiles(dir: string, acc: string[] = []): string[] {
  if (!existsSync(dir)) {
    return acc;
  }
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'dist-esm') {
        continue;
      }
      tsFiles(full, acc);
    } else if (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx')) {
      acc.push(full);
    }
  }
  return acc;
}

/**
 * Leg A — the stack topology's own answer, read off the AST rather than a
 * regex over the file. `SERVICES` is an array of object literals; a service
 * participates when its `kekAlias` property is anything other than `null`.
 */
function topologyServices(): { withKek: string[]; withoutKek: string[] } {
  const source = parse(TOPOLOGY);
  const withKek: string[] = [];
  const withoutKek: string[] = [];

  const readEntry = (node: ts.ObjectLiteralExpression): void => {
    let name: string | null = null;
    let hasKek: boolean | null = null;
    for (const prop of node.properties) {
      if (!ts.isPropertyAssignment(prop) || !ts.isIdentifier(prop.name)) {
        continue;
      }
      if (prop.name.text === 'name' && ts.isStringLiteralLike(prop.initializer)) {
        name = prop.initializer.text;
      }
      if (prop.name.text === 'kekAlias') {
        hasKek = prop.initializer.kind !== ts.SyntaxKind.NullKeyword;
      }
    }
    if (name !== null && hasKek !== null) {
      (hasKek ? withKek : withoutKek).push(name);
    }
  };

  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === 'SERVICES' &&
      node.initializer !== undefined
    ) {
      const array = ts.isAsExpression(node.initializer)
        ? node.initializer.expression
        : node.initializer;
      if (ts.isArrayLiteralExpression(array)) {
        for (const element of array.elements) {
          if (ts.isObjectLiteralExpression(element)) {
            readEntry(element);
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { withKek: withKek.sort(), withoutKek: withoutKek.sort() };
}

/**
 * Leg B — services whose migrations create a DEK table. Matched on a name
 * ENDING in `deks` because the eight do not agree on a prefix; anchoring on one
 * spelling is how a fence goes green while seeing three of eight.
 */
function servicesWithDekTable(): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(SERVICES_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory()) {
      continue;
    }
    const migrations = join(SERVICES_DIR, entry.name, 'migrations');
    if (!existsSync(migrations)) {
      continue;
    }
    const creates = readdirSync(migrations)
      .filter((f) => f.endsWith('.sql'))
      .some((f) =>
        /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[a-z_]*deks\b/i.test(
          readFileSync(join(migrations, f), 'utf8'),
        ),
      );
    if (creates) {
      found.push(entry.name);
    }
  }
  return found.sort();
}

/** Leg C — does this service's DEK repository declare `markDestroyed`? */
function implementsMarkDestroyed(service: string): boolean {
  const repo = join(SERVICES_DIR, service, 'src', 'dek.repository.ts');
  if (!existsSync(repo)) {
    return false;
  }
  let found = false;
  const visit = (node: ts.Node): void => {
    if (
      ts.isMethodDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === 'markDestroyed'
    ) {
      found = true;
    }
    ts.forEachChild(node, visit);
  };
  visit(parse(repo));
  return found;
}

/**
 * Leg D — every file that CALLS `destroyDek`, as an AST call expression rather
 * than a text match. A grep is not a parse: the identifier appears in this
 * file's own docstring, in `dek.ts`'s comments and in four docs, none of which
 * is a call.
 *
 * The method DECLARATION is deliberately not a call and does not appear here.
 */
function destroyDekCallers(): string[] {
  const roots = [join(REPO_ROOT, 'apps'), join(REPO_ROOT, 'packages')];
  const callers = new Set<string>();
  for (const root of roots) {
    for (const file of tsFiles(root)) {
      const source = parse(file);
      const visit = (node: ts.Node): void => {
        if (
          ts.isCallExpression(node) &&
          ts.isPropertyAccessExpression(node.expression) &&
          node.expression.name.text === 'destroyDek'
        ) {
          callers.add(relative(REPO_ROOT, file));
        }
        ts.forEachChild(node, visit);
      };
      visit(source);
    }
  }
  return [...callers].sort();
}

/**
 * The `domain` CHECK vocabulary from the progress ledger's DDL.
 *
 * READS THE CONSTRAINT, not a comment beside it and not the seed statement: the
 * CHECK is what Postgres enforces, so it is what a row can actually carry. A
 * scan anchored on anything else would go green against a constraint that had
 * quietly stopped matching.
 */
function progressDomainVocabulary(): string[] {
  const sql = readFileSync(PROGRESS_DDL, 'utf8');
  const check = /CHECK\s*\(domain\s+IN\s*\(([^)]*)\)\)/i.exec(sql);
  const body = check?.[1];
  if (body === undefined) {
    return [];
  }
  return [...body.matchAll(/'([^']+)'/g)].flatMap((m) => (m[1] === undefined ? [] : [m[1]])).sort();
}

describe('the erasure boundary is derived, not listed', () => {
  const { withKek, withoutKek } = topologyServices();

  it('finds the topology at all (anti-vacuity)', () => {
    expect(withKek.length).toBeGreaterThanOrEqual(MIN_DOMAINS);
    // Both arms populated: a parser that read `kekAlias` as always-null would
    // put every service in `withoutKek` and still satisfy a one-sided check.
    expect(withoutKek.length).toBeGreaterThanOrEqual(2);
  });

  it('the participant set agrees with the DEK tables the migrations create', () => {
    // Two derivations, neither aware of the other. Sets, not counts.
    expect(withKek).toEqual(servicesWithDekTable());
  });

  it('vault and audit are excluded, and that is a decision with a reason', () => {
    // Zone A holds no server-side key material (its shred is `POST
    // /v1/vault/reset`); audit holds entity ids and enums, never ciphertext.
    expect(withoutKek).toEqual(['audit', 'vault']);
    expect(servicesWithDekTable()).not.toContain('vault');
    expect(servicesWithDekTable()).not.toContain('audit');
  });

  it('the progress ledger names every participant and nothing else', () => {
    // Leg E. Three spellings of one list — the topology (what the runtime
    // wraps keys with), the DDL CHECK (what a row may carry), and the constant
    // the driver seeds from — compared as sets so a swap cannot hide in a
    // matching count. A ninth KEK-holding service turns this red in both
    // places until it is named.
    const vocabulary = progressDomainVocabulary();
    expect(vocabulary.length).toBeGreaterThanOrEqual(MIN_DOMAINS);
    expect(vocabulary).toEqual(withKek);
    expect([...ERASURE_DOMAINS].sort()).toEqual(withKek);
  });

  it('every participant can record a destruction — the storage primitive exists', () => {
    const missing = withKek.filter((service) => !implementsMarkDestroyed(service));
    expect(missing).toEqual([]);
  });

  it('the caller scan can see a call at all (positive control for the next assertion)', () => {
    // THE ASSERTION BELOW IS AN ABSENCE, which is the shape that passes when
    // the walker is broken. This points the same walker at the one call site
    // that exists and demands it be found.
    expect(destroyDekCallers()).toContain(KNOWN_TEST_CALLER);
  });

  it('the declared components exist — an allowlist of missing files permits nothing', () => {
    // A prefix that matches no file refuses every caller and reads as a
    // working control. Renaming the driver without touching this list is
    // exactly the drift that would leave the fence green and the rule gone.
    for (const component of ERASURE_COMPONENTS) {
      expect(existsSync(join(REPO_ROOT, component))).toBe(true);
    }
  });

  it('the production caller is inside a declared component (leg D is load-bearing)', () => {
    // The counterpart to the positive control above: it proves the walker can
    // SEE a call, this proves the allowlist is what PERMITS one. Together they
    // rule out the two ways the absence assertion below could pass for free.
    const production = destroyDekCallers().filter(
      (file) => !file.startsWith(join('packages', 'crypto', 'test')),
    );
    expect(production).not.toEqual([]);
    expect(production).toEqual([join('apps', 'services', 'identity', 'src', 'erasure.service.ts')]);
  });

  it('nothing outside a declared erasure component calls destroyDek', () => {
    const undeclared = destroyDekCallers().filter(
      (file) =>
        !file.startsWith(join('packages', 'crypto', 'test')) &&
        !ERASURE_COMPONENTS.some((prefix) => file.startsWith(prefix)),
    );
    expect(undeclared).toEqual([]);
  });
});
