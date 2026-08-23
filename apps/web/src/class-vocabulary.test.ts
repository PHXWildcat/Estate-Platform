/**
 * @jest-environment node
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import tailwindcss from '@tailwindcss/postcss';
import postcss from 'postcss';
import ts from 'typescript';

/**
 * EVERY CLASS THIS APP NAMES MUST BE A CLASS THE BROWSER HAS A RULE FOR.
 *
 * The defect this closes renders as nothing at all. `VaultLaunch` and
 * `OperatorLaunch` were written against a vocabulary — `panel`, `panel-title`,
 * `panel-note`, `button-primary` — that no stylesheet in this repo has ever
 * defined, so `/vault` and `/operator` served their headings as body text and
 * their primary buttons as bare words: transparent background, no padding, no
 * border. Nothing failed. TypeScript is happy (a className is a string),
 * eslint is happy, every unit test is happy, and the page renders — it just
 * renders unstyled. The only observer that could see it was a browser, and
 * `/vault` is the page that explains the Zone A trust boundary before the
 * step-up prompt that opens the vault.
 *
 * Widening this from those two files found four more instances in four more
 * components on the first run: `label`/`input` where the vocabulary is
 * `field-label`/`field-input` (EstateDistributions, ReportDeathFlow,
 * SettlementCases), `bg-surface-sunken` where the theme key is `--color-sunken`
 * and so the utility is `bg-sunken` (UnverifiedAddressBanner), and `notice`,
 * which never existed (Dashboard). A rule applied to one member of a category
 * is a rule half-applied.
 *
 * ── THE ORACLE ─────────────────────────────────────────────────────────────
 *
 * The question is NOT "is this a Tailwind utility or one of ours" — that split
 * is unanswerable without hand-listing Tailwind's grammar, and a hand-listed
 * set beside a thing that grows is this repo's most repeated defect. The
 * question is "does the stylesheet the browser receives contain a rule for this
 * class", and there is exactly one thing that can answer it: the stylesheet the
 * browser receives.
 *
 * So this compiles `src/app/globals.css` through the app's OWN PostCSS
 * pipeline — the same `@tailwindcss/postcss` plugin `postcss.config.mjs` names,
 * over the same source tree — and reads the class selectors out of the result.
 * Both halves of the vocabulary fall out of one derived set: `.card` and
 * `.btn-primary` because `@layer components` declares them, `.mt-2` and
 * `.text-ink-muted` and `.max-w-[12rem]` because Tailwind generated them for
 * this app's sources. `.panel-title` is absent because nothing anywhere can
 * make it exist. The two halves are still reported separately below, because a
 * fence that stopped seeing one of them would otherwise go quietly green.
 *
 * ── THE CORPUS, stated because a fence whose input is narrower than its claim
 * goes green for the same reason it is wrong ────────────────────────────────
 *
 * Files: every `.ts`/`.tsx` under `apps/web/src`, excluding `*.test.ts(x)` and
 * `*.d.ts`. NOT `apps/operator-web` or `apps/vault-web` — those are static
 * pages with their own hand-written `public/styles.css` and no Tailwind, so
 * they need their own fence and would fail this one for the wrong reason.
 *
 * Class strings, collected from the TypeScript AST rather than by grep, since a
 * grep for `className="…"` cannot see `className={STAT_LABEL}` and would state
 * a claim about all of them while checking two thirds:
 *
 *   1. Every string literal and template quasi in the VALUE position of a JSX
 *      `className` attribute. Value position excludes a conditional's test and
 *      both sides of a comparison — `className={role === 'user' ? 'text-right'
 *      : ''}` names one class, not two, and an oracle that thinks `user` is a
 *      class reports a defect that is not there.
 *   2. Every string literal in an object property literally named `className`
 *      (`{ label: 'Step-up fresh', className: 'chip chip-success' }`).
 *   3. One hop through a name referenced from (1): a top-level `const`'s
 *      initializer, or a top-level function's `return` expressions, resolved in
 *      the file itself or in the file that name is imported from. This is what
 *      reaches `STAT_LABEL`, `SEVERITY_CHIP` and `executionStatusTone`.
 *
 * What that leaves out, said plainly: a class assembled at runtime from pieces
 * (`` `text-${tone}` ``), or returned by something more than one hop away. The
 * partial token either side of a `${}` is DROPPED rather than checked, so the
 * corpus under-reports there instead of inventing failures. No such site exists
 * in the tree today, and the floors below are what would notice if the reach of
 * this scan ever collapsed.
 */

const WEB_ROOT = resolve(__dirname, '..');
const SRC = join(WEB_ROOT, 'src');
const GLOBALS_CSS = join(SRC, 'app', 'globals.css');

/** Where a class name was named, for a failure message that can be acted on. */
type Sites = ReadonlyMap<string, ReadonlySet<string>>;

interface ClassLiteral {
  readonly text: string;
  readonly file: string;
  readonly line: number;
  /** Preceded by a `${}`, so its first token may be half a class name. */
  readonly afterSubstitution: boolean;
  /** Followed by a `${}`, so its last token may be half a class name. */
  readonly beforeSubstitution: boolean;
}

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir).sort()) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      sourceFiles(path, out);
    } else if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry) && !/\.d\.ts$/.test(entry)) {
      out.push(path);
    }
  }
  return out;
}

const FILES = sourceFiles(SRC);
const SOURCES = new Map<string, ts.SourceFile>(
  FILES.map((file) => [
    file,
    // Parsed, never evaluated, and always as TSX: reading a constant must not
    // run the file, and `.ts` files in this corpus carry class strings too.
    ts.createSourceFile(
      file,
      readFileSync(file, 'utf8'),
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TSX,
    ),
  ]),
);

const rel = (file: string): string => relative(WEB_ROOT, file).split(sep).join('/');
const lineOf = (sf: ts.SourceFile, node: ts.Node): number =>
  sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;

/** Which corpus file a relative import resolves to, or null if it leaves it. */
function resolveImport(fromFile: string, specifier: string): string | null {
  if (!specifier.startsWith('.')) return null;
  const base = resolve(dirname(fromFile), specifier);
  for (const candidate of [
    `${base}.tsx`,
    `${base}.ts`,
    join(base, 'index.tsx'),
    join(base, 'index.ts'),
  ]) {
    if (SOURCES.has(candidate)) return candidate;
  }
  return null;
}

/**
 * Class strings in the VALUE position of an expression, plus the names it
 * references. A conditional's test and a comparison's operands are not values
 * this attribute can render, so they are not walked — see the corpus note.
 */
function collect(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
  sink: ClassLiteral[],
  names: Set<string> | null,
): void {
  const push = (
    text: string,
    at: ts.Node,
    afterSubstitution: boolean,
    beforeSubstitution: boolean,
  ): void => {
    sink.push({ text, file, line: lineOf(sf, at), afterSubstitution, beforeSubstitution });
  };

  const visit = (n: ts.Node): void => {
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
      push(n.text, n, false, false);
      return;
    }
    if (ts.isTemplateExpression(n)) {
      push(n.head.text, n, false, true);
      n.templateSpans.forEach((span, index) => {
        push(span.literal.text, n, true, index < n.templateSpans.length - 1);
        visit(span.expression);
      });
      return;
    }
    if (ts.isIdentifier(n)) {
      names?.add(n.text);
      return;
    }
    // A property NAME is not a value reference: `chip.className` names `chip`.
    if (ts.isPropertyAccessExpression(n)) return visit(n.expression);
    if (ts.isElementAccessExpression(n)) {
      visit(n.expression);
      return visit(n.argumentExpression);
    }
    if (ts.isCallExpression(n)) {
      visit(n.expression);
      n.arguments.forEach(visit);
      return;
    }
    if (ts.isConditionalExpression(n)) {
      visit(n.whenTrue);
      return visit(n.whenFalse);
    }
    if (ts.isBinaryExpression(n)) {
      const op = n.operatorToken.kind;
      if (op === ts.SyntaxKind.AmpersandAmpersandToken) return visit(n.right);
      if (
        op === ts.SyntaxKind.BarBarToken ||
        op === ts.SyntaxKind.QuestionQuestionToken ||
        op === ts.SyntaxKind.PlusToken
      ) {
        visit(n.left);
        return visit(n.right);
      }
      // A comparison yields a boolean; neither operand can be a class.
      return;
    }
    ts.forEachChild(n, visit);
  };

  visit(node);
}

/** Top-level value declarations and named imports, per file — the one hop. */
const topLevel = new Map<string, Map<string, ts.Node>>();
const importedFrom = new Map<string, Map<string, string>>();
for (const [file, sf] of SOURCES) {
  const declarations = new Map<string, ts.Node>();
  const imports = new Map<string, string>();
  for (const statement of sf.statements) {
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name) && declaration.initializer) {
          declarations.set(declaration.name.text, declaration.initializer);
        }
      }
    } else if (ts.isFunctionDeclaration(statement) && statement.name && statement.body) {
      declarations.set(statement.name.text, statement.body);
    } else if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      const target = resolveImport(file, statement.moduleSpecifier.text);
      const bindings = statement.importClause?.namedBindings;
      if (target !== null && bindings && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) imports.set(element.name.text, target);
      }
    }
  }
  topLevel.set(file, declarations);
  importedFrom.set(file, imports);
}

const attributeLiterals: ClassLiteral[] = [];
const hopLiterals: ClassLiteral[] = [];
/** Files in which the AST found at least one `className` attribute. */
const filesWithAttribute = new Set<string>();
let attributeCount = 0;

for (const [file, sf] of SOURCES) {
  const referenced = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (ts.isJsxAttribute(n) && ts.isIdentifier(n.name) && n.name.text === 'className') {
      attributeCount += 1;
      filesWithAttribute.add(file);
      if (n.initializer) collect(n.initializer, sf, file, attributeLiterals, referenced);
    }
    if (
      ts.isPropertyAssignment(n) &&
      (ts.isIdentifier(n.name) || ts.isStringLiteral(n.name)) &&
      n.name.text === 'className'
    ) {
      collect(n.initializer, sf, file, attributeLiterals, null);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);

  for (const name of referenced) {
    const owner = topLevel.get(file)?.has(name) === true ? file : importedFrom.get(file)?.get(name);
    if (owner === undefined) continue;
    const declaration = topLevel.get(owner)?.get(name);
    const ownerSource = SOURCES.get(owner);
    if (!declaration || !ownerSource) continue;
    if (ts.isBlock(declaration)) {
      const returns: ts.Expression[] = [];
      const findReturns = (n: ts.Node): void => {
        if (ts.isReturnStatement(n) && n.expression) returns.push(n.expression);
        ts.forEachChild(n, findReturns);
      };
      findReturns(declaration);
      for (const expression of returns) collect(expression, ownerSource, owner, hopLiterals, null);
    } else {
      collect(declaration, ownerSource, owner, hopLiterals, null);
    }
  }
}

/** Class name -> the `file:line` sites that name it. */
const used: Map<string, Set<string>> = new Map();
for (const literal of [...attributeLiterals, ...hopLiterals]) {
  let tokens = literal.text.split(/\s+/);
  // A token touching a `${}` is half a name. Dropped, never checked: this scan
  // under-reports at those seams rather than inventing a failure there.
  if (literal.afterSubstitution && !/^\s/.test(literal.text)) tokens = tokens.slice(1);
  if (literal.beforeSubstitution && !/\s$/.test(literal.text)) tokens = tokens.slice(0, -1);
  for (const token of tokens) {
    if (token === '') continue;
    const sites = used.get(token) ?? new Set<string>();
    sites.add(`${rel(literal.file)}:${literal.line}`);
    used.set(token, sites);
  }
}
const USED: Sites = used;

/** Class selectors in a stylesheet, unescaped (`.sm\:p-6` -> `sm:p-6`). */
function classesIn(root: postcss.Root): Set<string> {
  const found = new Set<string>();
  root.walkRules((rule) => {
    for (const match of rule.selector.matchAll(/\.((?:\\.|[^\s.,>+~()[\]{}:#"'\\])+)/g)) {
      const name = match[1];
      if (name !== undefined) found.add(name.replace(/\\(.)/g, '$1'));
    }
  });
  return found;
}

/** What `@layer components` in globals.css declares, read from the file itself. */
function declaredInGlobals(): Set<string> {
  return classesIn(postcss.parse(readFileSync(GLOBALS_CSS, 'utf8'), { from: GLOBALS_CSS }));
}

/** The stylesheet the browser receives, through the app's own pipeline. */
async function compiledClasses(): Promise<Set<string>> {
  const result = await postcss([tailwindcss({ base: WEB_ROOT })]).process(
    readFileSync(GLOBALS_CSS, 'utf8'),
    { from: GLOBALS_CSS },
  );
  return classesIn(result.root);
}

describe('the class vocabulary this app names is the one its stylesheet defines', () => {
  let defined: Set<string>;
  let handWritten: Set<string>;

  beforeAll(async () => {
    defined = await compiledClasses();
    handWritten = declaredInGlobals();
  });

  it('scans the whole source tree, not a subset of it', () => {
    // A count alone cannot tell a shrinking corpus from a shrinking app, so the
    // set is named as well: a walk that stopped descending into `components/`
    // or into the route groups would still return files.
    expect(FILES.length).toBeGreaterThanOrEqual(80);
    const names = new Set(FILES.map(rel));
    for (const required of [
      'src/components/VaultLaunch.tsx',
      'src/components/OperatorLaunch.tsx',
      'src/components/SecurityPanel.tsx',
      'src/components/Dashboard.tsx',
      'src/app/(app)/security/page.tsx',
      'src/app/(app)/vault/page.tsx',
      'src/lib/stat.ts',
    ]) {
      expect(names).toContain(required);
    }
    // Tests are excluded on purpose (they assert about classes rather than
    // ship them) — and the exclusion must not be silently total.
    expect(names).not.toContain('src/components/VaultLaunch.test.tsx');
  });

  it('finds a className attribute in every file that has one', () => {
    // TWO INDEPENDENT OBSERVERS. The parser is the one that matters; a plain
    // text scan is the one that cannot be broken by a parser bug. Compared as
    // SETS at file level rather than as a total, because a parser that silently
    // skipped one file would keep a plausible-looking count.
    const byText = new Set<string>();
    for (const [file, sf] of SOURCES) {
      const code = sf.text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
      if (code.includes('className=')) byText.add(file);
    }
    expect([...filesWithAttribute].map(rel).sort()).toEqual([...byText].map(rel).sort());
    expect(attributeCount).toBeGreaterThanOrEqual(500);
  });

  it('reads classes out of both static and computed className expressions', () => {
    expect(USED.size).toBeGreaterThanOrEqual(150);
    // POSITIVE CONTROL on the extractor's reach: one class from each of the
    // three collection rules. If any rule stops matching, the fence goes green
    // over everything that rule was the only way to see.
    expect(USED.has('card')).toBe(true); //           (1) `className="card p-6"`
    expect(USED.has('chip-success')).toBe(true); //   (2) `{ className: 'chip chip-success' }`
    expect(USED.has('tracking-[0.08em]')).toBe(true); // (3) via `STAT_LABEL`
    // NEGATIVE CONTROL on the extractor: `role === 'user'` is a comparison, and
    // `user` is not a class this app names.
    expect(USED.has('user')).toBe(false);
  });

  it('compiles globals.css into a stylesheet that defines both halves of the vocabulary', () => {
    expect(defined.size).toBeGreaterThanOrEqual(150);
    // The hand-written layer must survive the compile whole — if `@layer
    // components` were dropped, every app class would read as undefined and
    // this fence would report the entire app as broken rather than go green,
    // but say so here where the message is the true one.
    expect(handWritten.size).toBeGreaterThanOrEqual(15);
    expect([...handWritten].filter((name) => !defined.has(name))).toEqual([]);
    // And Tailwind must have generated its half: the compiled set is much more
    // than what the file itself declares.
    const generated = [...defined].filter((name) => !handWritten.has(name));
    expect(generated.length).toBeGreaterThanOrEqual(100);
  });

  it('cannot answer yes to a class nothing defines', () => {
    // THE ORACLE MUST BE ABLE TO SAY NO, tested with the exact names that
    // caused the defect. Without this, a `defined` set that accidentally
    // contained everything — a selector regex that matched too much, a compile
    // that emitted a catch-all — would pass every other assertion in this file.
    for (const absent of [
      'panel',
      'panel-title',
      'panel-note',
      'button-primary',
      'notice',
      'bg-surface-sunken',
    ]) {
      expect(defined.has(absent)).toBe(false);
    }
  });

  it('names no class the stylesheet has no rule for', () => {
    const missing = [...USED.keys()].filter((name) => !defined.has(name)).sort();
    const report = missing.map(
      (name) => `  ${name} — ${[...(USED.get(name) ?? [])].sort().join(', ')}`,
    );
    expect(report).toEqual([]);
  });
});
