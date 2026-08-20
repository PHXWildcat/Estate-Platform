/**
 * A TEST THAT READS OUTSIDE ITS PACKAGE MUST SAY SO, OR IT CACHES GREEN WHILE
 * ITS ONLY INPUT CHANGES.
 *
 * Turbo's default input set for a `test` task is the package's own tracked
 * files. A spec that reaches into `docs/`, `.github/workflows/`, a compose file
 * or another package's `src/` therefore has inputs turbo cannot see: editing
 * one does not move the task hash, and `pnpm test` answers `cache hit,
 * replaying logs` for the one gate whose input just changed. The suite is
 * green, the gate is disarmed, and nothing says so.
 *
 * That is measured, not theorised. A docs edit that violated the §6 residual
 * tag grammar four ways passed locally as a replayed log from
 * `packages/contracts` and failed in CI, where the cache was cold. It is the
 * repo's own "a stale artifact is not evidence" rule, applied to a cache rather
 * than to a `dist`.
 *
 * WHY THIS IS A FENCE AND NOT ELEVEN CAREFULLY-WRITTEN FILES. The hole was
 * first found in one package and hand-listed as twelve specs across eight
 * packages. Deriving the same question from the AST found ELEVEN packages and
 * twenty specs — `apps/web` alone reaches into four other packages from five
 * different test files, and none of those had been noticed. A hand-maintained
 * list beside a thing that grows is this repo's most repeated defect, so the
 * corpus here is every test file in every workspace package, every time.
 *
 * WHAT COUNTS AS REACHING OUTSIDE. A `join`/`resolve` rooted at `__dirname`
 * whose LITERAL prefix resolves outside the package directory, or any
 * `process.cwd()`. Arguments stop being followed at the first non-literal, so
 * `join(__dirname, '..', 'src', file)` — a variable filename under the
 * package's own `src` — resolves to `<pkg>/src` and is correctly INTERNAL.
 * That is a deliberate, stated limit rather than an oversight: treating an
 * unresolvable tail as an escape put `apps/services/identity` on this list for
 * reading its own controller, and a fence that demands a whole-repo hash for an
 * in-package read buys nothing and costs every PBKDF2 suite in that package. A
 * non-literal that escapes at RUNTIME is the residual, and it is small because
 * the literal prefix is what carries the `..` segments in every case here.
 *
 * WHY THE DECLARATION IS ONE CANONICAL LIST RATHER THAN A PRECISE ONE PER
 * PACKAGE. A precise list is a second copy of what the spec already names, free
 * to drift from it, and the two failure directions are not symmetric: too broad
 * re-runs a fast test, too narrow replays a stale pass on a gate nobody knows is
 * disarmed. Only one of those can ship a wrong answer. Several of these specs
 * sweep `apps/**` and `packages/**` at runtime anyway, so for them the whole
 * tree IS the honest input set.
 *
 * WHY THE EXCLUSIONS EXIST AT ALL, which is the part that was measured twice.
 * `$TURBO_DEFAULT$` is git-aware; an explicit `$TURBO_ROOT$` glob is NOT.
 * `["$TURBO_DEFAULT$", "$TURBO_ROOT$/**"]` alone sweeps in `node_modules`,
 * `dist`, `.turbo` and `.next`, and two identical consecutive runs produced
 * different hashes — a cache that can never hit. Appending one line to a
 * gitignored `dist/index.js` moved the hash on its own, which is the direct
 * proof that turbo hashes ignored files under an explicit glob. So the
 * exclusions re-apply .gitignore by hand, and `covers every ignored path`
 * below checks that hand against git's own answer rather than against a
 * comment. A missing exclusion makes the hash unstable — loud and slow. A
 * missing INPUT makes it stale — silent and wrong.
 */
import { execFileSync } from 'node:child_process';
import { type Dirent, existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import * as ts from 'typescript';

const REPO_ROOT = join(__dirname, '..', '..', '..');

/**
 * The declaration every package that reaches outside itself must carry, in this
 * order. Held here as DATA and copied into each `turbo.json`, so there is one
 * place to change it and this fence names every file that disagrees.
 */
const CANONICAL_TEST_INPUTS: readonly string[] = [
  '$TURBO_DEFAULT$',
  '$TURBO_ROOT$/**',
  '!$TURBO_ROOT$/**/node_modules/**',
  '!$TURBO_ROOT$/**/dist/**',
  '!$TURBO_ROOT$/**/dist-esm/**',
  '!$TURBO_ROOT$/**/.next/**',
  '!$TURBO_ROOT$/**/.turbo/**',
  '!$TURBO_ROOT$/**/coverage/**',
  '!$TURBO_ROOT$/**/.DS_Store',
  '!$TURBO_ROOT$/**/*.tsbuildinfo',
  '!$TURBO_ROOT$/**/next-env.d.ts',
  '!$TURBO_ROOT$/**/vault-extension.zip',
  '!$TURBO_ROOT$/.claude/**',
  '!$TURBO_ROOT$/.stack-certs/**',
  '!$TURBO_ROOT$/apps/operator-web/public/app/**',
  '!$TURBO_ROOT$/apps/vault-web/public/app/**',
  '!$TURBO_ROOT$/apps/vault-web/public/lib/**',
];

/** Build output that mutates, plus the caches turbo and jest keep beside it. */
const NEVER_DESCEND = new Set(['node_modules', 'dist', 'dist-esm', '.next', '.turbo', 'coverage']);

// ---------------------------------------------------------------------------
// The corpus: every workspace package, derived from pnpm-workspace.yaml.
// ---------------------------------------------------------------------------

/**
 * The workspace globs, read from `pnpm-workspace.yaml` rather than restated.
 * Only the `apps/*` shape is supported; anything else is REFUSED, because a
 * glob this cannot read would silently shrink the corpus and a fence with a
 * smaller corpus goes green for the same reason it is wrong.
 */
function workspaceGlobs(): string[] {
  const yaml = readFileSync(join(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8');
  const lines = yaml.split('\n');
  const start = lines.findIndex((l) => /^packages:\s*$/.test(l));
  if (start === -1) {
    throw new Error('pnpm-workspace.yaml: no `packages:` block — corpus would be empty');
  }
  const globs: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    if (/^\s*$/.test(line) || /^\s*#/.test(line)) continue;
    const m = /^\s+-\s+'?([^'\s]+)'?\s*$/.exec(line);
    if (!m)
      throw new Error(`pnpm-workspace.yaml: unreadable workspace entry ${JSON.stringify(line)}`);
    const glob = m[1] ?? '';
    if (!glob.endsWith('/*') || glob.slice(0, -2).includes('*')) {
      throw new Error(
        `pnpm-workspace.yaml: unsupported glob ${glob} — this fence reads only 'dir/*'`,
      );
    }
    globs.push(glob);
  }
  return globs;
}

/** Every workspace package, as a repo-relative posix path. */
function workspacePackages(): { globs: string[]; byGlob: Map<string, string[]>; all: string[] } {
  const globs = workspaceGlobs();
  const byGlob = new Map<string, string[]>();
  for (const glob of globs) {
    const parent = glob.slice(0, -2);
    const abs = join(REPO_ROOT, parent);
    const found = existsSync(abs)
      ? readdirSync(abs, { withFileTypes: true })
          .filter((e) => e.isDirectory())
          .map((e) => `${parent}/${e.name}`)
          .filter((rel) => existsSync(join(REPO_ROOT, rel, 'package.json')))
          .sort()
      : [];
    byGlob.set(glob, found);
  }
  const all = [...new Set([...byGlob.values()].flat())].sort();
  return { globs, byGlob, all };
}

/** Every test file inside a package, never descending into a nested package. */
function testFilesOf(pkg: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const child = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (NEVER_DESCEND.has(entry.name)) continue;
        // `apps/services/*` are packages in their own right and are walked as
        // themselves; descending would attribute their specs to `apps`.
        if (existsSync(join(child, 'package.json'))) continue;
        walk(child);
      } else if (/\.(spec|test)\.tsx?$/.test(entry.name)) {
        out.push(child);
      }
    }
  };
  walk(join(REPO_ROOT, pkg));
  return out.sort();
}

// ---------------------------------------------------------------------------
// The detector: which test files resolve a path outside their own package.
// ---------------------------------------------------------------------------

interface Escape {
  readonly file: string;
  readonly target: string;
}

const literalText = (node: ts.Node): string | null =>
  ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : null;

/**
 * Every path this file resolves outside its own package.
 *
 * Parsed with `ts.createSourceFile` rather than grepped: a regex over source
 * cannot tell `join(__dirname, '..')` in code from the same text inside a
 * string or a comment, and this repo has a decision-log entry for each time
 * that mattered.
 */
function escapesIn(file: string, pkgAbs: string): Escape[] {
  const source = ts.createSourceFile(
    file,
    readFileSync(file, 'utf8'),
    ts.ScriptTarget.Latest,
    true,
  );
  const dir = join(file, '..');
  const found: Escape[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const fn = node.expression;
      const name = ts.isIdentifier(fn)
        ? fn.text
        : ts.isPropertyAccessExpression(fn)
          ? fn.name.text
          : '';

      const rootedAtDirname =
        (name === 'join' || name === 'resolve') &&
        node.arguments.length > 0 &&
        ts.isIdentifier(node.arguments[0] as ts.Node) &&
        (node.arguments[0] as ts.Identifier).text === '__dirname';

      if (rootedAtDirname) {
        // Follow the LITERAL prefix only, and stop at the first argument whose
        // value this cannot know. See the header for why an unresolvable tail
        // under an in-package prefix is internal rather than an escape.
        const parts: string[] = [];
        for (const arg of node.arguments.slice(1)) {
          const text = literalText(arg);
          if (text === null) break;
          parts.push(text);
        }
        const target = resolve(dir, ...parts);
        if (relative(pkgAbs, target).startsWith('..')) {
          found.push({
            file: relative(REPO_ROOT, file).split(sep).join('/'),
            target: relative(REPO_ROOT, target).split(sep).join('/') || '<repo root>',
          });
        }
      }

      const isCwd =
        name === 'cwd' &&
        ts.isPropertyAccessExpression(fn) &&
        ts.isIdentifier(fn.expression) &&
        fn.expression.text === 'process';
      if (isCwd) {
        found.push({
          file: relative(REPO_ROOT, file).split(sep).join('/'),
          target: '<process.cwd()>',
        });
      }
    }
    ts.forEachChild(node, visit);
  };

  visit(source);
  return found;
}

// ---------------------------------------------------------------------------
// The exclusion matcher, so the canonical list is checked against git.
// ---------------------------------------------------------------------------

type Shape =
  | { kind: 'segment'; name: string }
  | { kind: 'prefix'; path: string }
  | { kind: 'basename'; name: string }
  | { kind: 'suffix'; ext: string };

/**
 * Four glob shapes are understood. Anything else THROWS rather than being
 * skipped: an exclusion this cannot read would otherwise be silently treated as
 * covering nothing, which is the permissive answer.
 */
function parseExclusion(glob: string): Shape {
  const prefix = '!$TURBO_ROOT$/';
  if (!glob.startsWith(prefix)) {
    throw new Error(`exclusion not rooted at $TURBO_ROOT$: ${glob}`);
  }
  const body = glob.slice(prefix.length);
  let m: RegExpExecArray | null;
  if ((m = /^\*\*\/([^/*]+)\/\*\*$/.exec(body))) return { kind: 'segment', name: m[1] as string };
  if ((m = /^\*\*\/\*(\.[A-Za-z0-9.]+)$/.exec(body)))
    return { kind: 'suffix', ext: m[1] as string };
  if ((m = /^\*\*\/([^/*]+)$/.exec(body))) return { kind: 'basename', name: m[1] as string };
  if ((m = /^([^*]+)\/\*\*$/.exec(body))) return { kind: 'prefix', path: m[1] as string };
  throw new Error(`unreadable exclusion glob: ${glob}`);
}

function coveredBy(shapes: readonly Shape[], path: string): boolean {
  const clean = path.replace(/\/$/, '');
  const segments = clean.split('/');
  const base = segments[segments.length - 1] as string;
  return shapes.some((s) =>
    s.kind === 'segment'
      ? segments.includes(s.name)
      : s.kind === 'prefix'
        ? clean === s.path || clean.startsWith(`${s.path}/`)
        : s.kind === 'basename'
          ? base === s.name
          : clean.endsWith(s.ext),
  );
}

// ---------------------------------------------------------------------------

const { globs, byGlob, all: PACKAGES } = workspacePackages();

const scanned = PACKAGES.map((pkg) => {
  const pkgAbs = join(REPO_ROOT, pkg);
  const files = testFilesOf(pkg);
  const escapes = files.flatMap((f) => escapesIn(f, pkgAbs));
  return { pkg, files, escapes };
});

const ESCAPING = scanned.filter((s) => s.escapes.length > 0).map((s) => s.pkg);
const CLEAN = scanned.filter((s) => s.escapes.length === 0).map((s) => s.pkg);

/** What each package's `turbo.json` declares for `test.inputs`, if anything. */
function declaredInputs(pkg: string): { present: boolean; extends?: unknown; inputs?: unknown } {
  const file = join(REPO_ROOT, pkg, 'turbo.json');
  if (!existsSync(file)) return { present: false };
  // turbo.json is JSONC in this repo (the root file is commented); strip
  // comments with the scanner rather than a regex, then parse.
  const raw = readFileSync(file, 'utf8');
  const parsed = ts.parseConfigFileTextToJson(file, raw);
  if (parsed.error) {
    throw new Error(`${pkg}/turbo.json is not parseable as JSONC`);
  }
  const config = parsed.config as { extends?: unknown; tasks?: { test?: { inputs?: unknown } } };
  return { present: true, extends: config.extends, inputs: config.tasks?.test?.inputs };
}

const DECLARING = PACKAGES.filter((pkg) => {
  const d = declaredInputs(pkg);
  return d.present && Array.isArray(d.inputs);
});

describe('the corpus this fence scans', () => {
  it('finds every workspace package, and every glob contributes some', () => {
    expect(globs.length).toBeGreaterThan(0);
    for (const glob of globs) {
      expect(`${glob}: ${(byGlob.get(glob) ?? []).length > 0}`).toBe(`${glob}: true`);
    }
    // Set comparison rather than a count: mis-attribution preserves counts.
    expect(PACKAGES).toContain('packages/config');
    expect(PACKAGES).toContain('apps/services/settlement');
    expect(PACKAGES).toContain('apps/web');
    expect(PACKAGES.length).toBeGreaterThanOrEqual(25);
  });

  it('reads test files in every package it scans — no package is silently empty', () => {
    const empty = scanned.filter((s) => s.files.length === 0).map((s) => s.pkg);
    expect(empty).toEqual([]);
    const total = scanned.reduce((n, s) => n + s.files.length, 0);
    expect(total).toBeGreaterThan(200);
  });

  it('separates escaping from clean packages — both arms are populated', () => {
    // The positive control. "Everything escapes" and "the detector is broken"
    // look identical without this, and so do "nothing escapes" and "the parser
    // matched nothing".
    expect(ESCAPING.length).toBeGreaterThan(0);
    expect(CLEAN.length).toBeGreaterThan(0);
    expect(CLEAN).toContain('packages/money');
    expect(CLEAN).toContain('apps/services/identity');
  });
});

describe('a test that reads outside its package declares it as a turbo input', () => {
  it('the set that needs the declaration is exactly the set that carries it', () => {
    // Both directions matter. A package missing the declaration caches a stale
    // pass; a package carrying one whose specs no longer reach outside is a
    // claim about the world that has stopped being true.
    expect(DECLARING).toEqual(ESCAPING);
  });

  it.each(ESCAPING)('%s declares the canonical inputs, in order', (pkg) => {
    const declared = declaredInputs(pkg);
    expect(`${pkg} has turbo.json: ${declared.present}`).toBe(`${pkg} has turbo.json: true`);
    // `extends` is load-bearing: without it a package-level config REPLACES the
    // root task rather than merging, dropping `dependsOn: ["^build"]` and the
    // `PG_TEST_URL`/`CI` env declarations, and the tests would run against a
    // stale `dist` instead.
    expect(declared.extends).toEqual(['//']);
    expect(declared.inputs).toEqual(CANONICAL_TEST_INPUTS);
  });

  it('names what each escaping package actually reaches, so the list is reviewable', () => {
    const report = scanned
      .filter((s) => s.escapes.length > 0)
      .map((s) => {
        const targets = [...new Set(s.escapes.map((e) => e.target))].sort();
        return `${s.pkg} -> ${targets.join(', ')}`;
      });
    // Anti-vacuity on the reach itself: every escaping package must name at
    // least one target, and no target may be the empty string.
    expect(report.length).toBe(ESCAPING.length);
    for (const line of report) {
      expect(line).toMatch(/ -> \S/);
    }
  });
});

describe('the canonical exclusions re-apply .gitignore, which $TURBO_ROOT$ globs do not', () => {
  const exclusions = CANONICAL_TEST_INPUTS.filter((i) => i.startsWith('!'));
  const shapes = exclusions.map(parseExclusion);

  it('every exclusion is a shape this fence can read', () => {
    expect(shapes.length).toBe(exclusions.length);
    expect(shapes.length).toBeGreaterThan(0);
  });

  it('the broad glob is present and comes before the exclusions', () => {
    expect(CANONICAL_TEST_INPUTS[0]).toBe('$TURBO_DEFAULT$');
    expect(CANONICAL_TEST_INPUTS[1]).toBe('$TURBO_ROOT$/**');
    const firstExclusion = CANONICAL_TEST_INPUTS.findIndex((i) => i.startsWith('!'));
    expect(firstExclusion).toBe(2);
  });

  it('matches the anchored build-output paths, not just the bare directory names', () => {
    // Pinned because a hand-check of this list using a shell `case` statement
    // reported these three as UNCOVERED and they are not — the `prefix` shape
    // matches them. The observation was broken, not the list, and the next
    // person to audit this by eye deserves the answer in a test rather than in
    // a comment.
    for (const path of [
      'apps/vault-web/public/app/',
      'apps/vault-web/public/lib/',
      'apps/operator-web/public/app/',
      'apps/web/.next/',
      'packages/money/node_modules/',
    ]) {
      expect(`${path} covered: ${coveredBy(shapes, path)}`).toBe(`${path} covered: true`);
    }
    // And the other arm: a source path must NOT be swept up by an exclusion.
    for (const path of ['apps/bff/src/schema.ts', 'docs/03-threat-model.md']) {
      expect(`${path} covered: ${coveredBy(shapes, path)}`).toBe(`${path} covered: false`);
    }
  });

  it('covers every path git reports as ignored, or names it as deliberately hashed', () => {
    const out = execFileSync(
      'git',
      ['ls-files', '--others', '--ignored', '--exclude-standard', '--directory'],
      { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
    );
    const ignored = out.split('\n').filter((l) => l.length > 0);

    // Anti-vacuity: an empty answer from git and a fully-covered tree look
    // identical. `node_modules` exists whenever this suite can run at all.
    expect(ignored.length).toBeGreaterThan(0);
    expect(ignored.some((p) => p.split('/').includes('node_modules'))).toBe(true);

    const uncovered = ignored.filter((p) => !coveredBy(shapes, p));
    // An uncovered path is allowed only if it is one this repo means to hash.
    // `.env.stack` is generated and gitignored, and `apps/e2e`'s stack spec
    // READS it — excluding it would recreate this PR's exact defect in the one
    // package whose only external read it is. It is stable between
    // regenerations, so hashing it costs a re-run when the stack env changes,
    // which is the correct answer rather than a tolerated one.
    const deliberatelyHashed = (p: string): boolean => /(^|\/)\.env(\.|$)/.test(p);
    const unexplained = uncovered.filter((p) => !deliberatelyHashed(p));

    // A miss here does not ship a wrong answer — it makes the hash move on
    // every build, so the cache never hits and the tests always run. Loud and
    // slow, which is the direction this whole fence is choosing.
    expect(unexplained).toEqual([]);
  });
});
