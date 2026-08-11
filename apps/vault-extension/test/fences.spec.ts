/**
 * THE EXTENSION'S FENCES (M16 PR2a).
 *
 * The vault ORIGIN got seven of these in M15 PR1, because docs/03 rates
 * client-side compromise Critical and the realistic regression is never a
 * deliberate weakening — it is a second surface importing vault crypto, a
 * convenience dependency, a `console.log` added while debugging, or one
 * `innerHTML` in a hurry.
 *
 * THIS ARTIFACT NEEDS THEM MORE, and PR2a is the moment to establish them:
 * everything here is still transport, so a fence that fails now costs an edit
 * rather than a redesign. It is also the one thing in the product distributed
 * as a SIGNED, AUTO-UPDATED BLOB through a vendor store with no CSP in its
 * path, where docs/03 §4 TB9 records a compromised update as undetectable by
 * the platform — so "what ships is exactly what a reviewer reads" is the
 * compensating control, and these are what keep it true.
 *
 * Every one is MUTATION-TESTED red before green; a fence that has never failed
 * has never been tested. The mechanism throughout is `readFileSync` over the
 * source — the @estate/vault-crypto zero-dependency-fence precedent, which
 * creates no package edge and therefore cannot be defeated by how a module
 * happens to be wired.
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(__dirname, '..');
const SRC = join(ROOT, 'src');

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (current: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.name.endsWith('.ts')) out.push(path);
    }
  };
  walk(dir);
  return out;
}

const sourceFiles = filesUnder(SRC);

/**
 * The ONE non-relative specifier this artifact may import. A leading slash
 * resolves against the extension's own root, so vault-crypto ships inside the
 * signed package (MV3 forbids remotely hosted code) and no bare specifier ever
 * reaches the browser.
 */
const VAULT_CRYPTO_SPECIFIER = '/lib/vault-crypto/index.js';

/** Comments name these things constantly; only real code counts. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

function code(file: string): string {
  return stripComments(readFileSync(file, 'utf8'));
}

function importSpecifiers(file: string): string[] {
  const source = code(file);
  const patterns = [
    /^\s*import\s[\s\S]*?from\s*['"]([^'"]+)['"]/gm,
    /^\s*import\s*['"]([^'"]+)['"]/gm,
    /^\s*export\s[\s\S]*?from\s*['"]([^'"]+)['"]/gm,
    /\bimport\s*\(\s*['"]([^'"]+)['"]/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]/g,
  ];
  return patterns.flatMap((pattern) => [...source.matchAll(pattern)].map((m) => m[1] ?? ''));
}

describe('the extension has no dependency tree', () => {
  it('finds the files it is meant to be checking', () => {
    // Never pass vacuously — the credential-graph anti-drop lesson.
    expect(sourceFiles.length).toBeGreaterThan(4);
  });

  it.each(sourceFiles)('%s imports only relative paths or the vault crypto', (file) => {
    for (const specifier of importSpecifiers(file)) {
      // Relative (with an explicit .js, since these are native ES modules), or
      // the ONE workspace package this artifact may load — by an absolute path
      // that resolves against the EXTENSION's own root, so no bare specifier
      // reaches the browser and there is no import map for a CSP to admit.
      const permitted =
        specifier.startsWith('./') ||
        specifier.startsWith('../') ||
        specifier === VAULT_CRYPTO_SPECIFIER;
      expect({ file, specifier, permitted }).toEqual({ file, specifier, permitted: true });
    }
  });

  it('relative imports carry an explicit .js, or the browser cannot resolve them', () => {
    for (const file of sourceFiles) {
      for (const specifier of importSpecifiers(file)) {
        if (!specifier.startsWith('.')) continue;
        expect({ file, specifier, ok: specifier.endsWith('.js') }).toEqual({
          file,
          specifier,
          ok: true,
        });
      }
    }
  });

  it('declares NO dependencies at all — not even dev ones beyond the toolchain', () => {
    /*
     * Stricter than `vault-web`, which may use zod in its Node edge. There is
     * no server here: every line ships to a browser inside a signed artifact,
     * so the runtime dependency list is empty and the dev list is the build and
     * test toolchain only.
     *
     * `@types/chrome` is deliberately ABSENT. The four platform members this
     * package uses are declared by hand in `src/chrome.d.ts`, which makes the
     * extension-API surface as visible in review as the manifest's permissions.
     *
     * `@estate/vault-crypto` is a DEV dependency and not a runtime one, which
     * is a statement rather than a technicality — the `vault-web` precedent,
     * for the same reason. Nothing resolves it as a package at runtime: the
     * offscreen worker loads it by absolute path from the extension's own root,
     * and it is here so turbo orders that package's build first and so the
     * suite can drive the server half of SRP. Promoting it to `dependencies`
     * would erase that distinction.
     */
    // Read rather than imported, like every other scan here: the manifest is
    // checked as the bytes on disk, not as a shape TypeScript inferred.
    const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies: Record<string, string>;
    };
    expect(manifest.dependencies).toBeUndefined();
    expect(Object.keys(manifest.devDependencies).sort()).toEqual([
      '@estate/config',
      '@estate/vault-crypto',
      '@types/jest',
      '@types/node',
      'jest',
      'jest-environment-jsdom',
      'ts-jest',
      'typescript',
    ]);
  });

  /**
   * EXACTLY ONE FILE MAY LOAD ZONE A's CRYPTO (M16 PR2b).
   *
   * PR2a's version of this asserted the extension imported it NOWHERE, and
   * said that PR2b adding it had to be a declared change rather than a
   * discovery. It was: writing `vault-worker-core.ts` turned that assertion
   * red, and this is the deliberate edit — narrowed rather than deleted.
   *
   * Narrowed to the KEY HOLDER, because "which file can construct a vault key"
   * is the whole security shape of this artifact. Anything that can import the
   * crypto can derive from a password and a Secret Key; keeping that to one
   * module is what makes the popup, the service worker and (in PR3) the content
   * script structurally incapable of it, rather than merely not currently doing
   * it.
   */
  it('only the key holder may import the vault crypto', () => {
    const importers = sourceFiles.filter((file) =>
      importSpecifiers(file).includes(VAULT_CRYPTO_SPECIFIER),
    );
    expect(importers.map((f) => f.slice(SRC.length + 1))).toEqual(['vault-worker-core.ts']);
  });

  it('and it really does import it, so the fence is not vacuous', () => {
    expect(importSpecifiers(join(SRC, 'vault-worker-core.ts'))).toContain(VAULT_CRYPTO_SPECIFIER);
  });
});

describe('the SHIPPED artifact is compiled against a browser surface only', () => {
  /**
   * The two-config split is only a fence if the emitting config is the strict
   * one. `tsconfig.json` carries `node` types because the SUITE runs in Node —
   * these scans read files, and the manifest test spawns the real build — so
   * without this, a `src` module could reach for `process` or `Buffer`, pass
   * typecheck, and fail in a user's browser.
   *
   * Asked of TSC rather than parsed out of the file, and that is the point
   * rather than fastidiousness: `tsconfig.build.json` is JSONC and it EXTENDS
   * another config, so reading it here would test this file's own text while
   * the compiler resolves something else. `--showConfig` is what tsc actually
   * decided, inheritance included.
   */
  const resolved = JSON.parse(
    execFileSync(
      process.execPath,
      [
        require.resolve('typescript/bin/tsc'),
        '--showConfig',
        '-p',
        join(ROOT, 'tsconfig.build.json'),
      ],
      { cwd: ROOT, encoding: 'utf8' },
    ),
  ) as { compilerOptions: Record<string, unknown>; files?: string[] };

  it('emits with NO ambient type packages, so Node globals do not compile', () => {
    expect(resolved.compilerOptions['types']).toEqual([]);
  });

  it('emits only src — the suite is never part of the artifact', () => {
    expect(resolved.compilerOptions['outDir']).toContain('dist');
    for (const file of resolved.files ?? []) {
      expect({ file, inSrc: file.includes('/src/') }).toEqual({ file, inSrc: true });
    }
  });

  it('really resolved a config (so the assertions are not true of nothing)', () => {
    expect((resolved.files ?? []).length).toBeGreaterThan(4);
  });
});

describe('no HTML sinks anywhere in this package', () => {
  /**
   * ZERO declared exemptions, like the vault origin and unlike the main app.
   * MV3's default extension CSP already forbids inline script and `eval`; this
   * catches the mistake at build time instead of shipping a popup that breaks
   * at runtime, and it covers the DOM sinks the CSP does not.
   */
  const SINKS = [
    'innerHTML',
    'outerHTML',
    'insertAdjacentHTML',
    'document.write',
    'eval(',
    'new Function',
    'dangerouslySetInnerHTML',
  ];

  it.each(sourceFiles)('%s contains no HTML/script sink', (file) => {
    const source = code(file);
    for (const sink of SINKS) {
      expect({ file, sink, found: source.includes(sink) }).toEqual({ file, sink, found: false });
    }
  });

  it('the popup shell has no inline script and no inline style', () => {
    const html = readFileSync(join(ROOT, 'public', 'popup.html'), 'utf8');
    expect(html).not.toMatch(/<script(?![^>]*\ssrc=)/i);
    expect(html).not.toMatch(/\sstyle=/i);
  });
});

describe('the network has exactly one call site', () => {
  /**
   * THE FENCE PR2b'S CENTRAL CLAIM WILL REST ON, established while there is
   * still nothing to protect.
   *
   * Once keys exist, "nothing derived from the vault password or the Secret Key
   * leaves the device" has to be checkable rather than re-argued per screen —
   * and it is checkable exactly when there is ONE call site to audit. Building
   * that now is cheaper than retrofitting it around code that already handles
   * key material.
   */
  const EGRESS = [
    'fetch(',
    'XMLHttpRequest',
    'sendBeacon',
    'new WebSocket',
    'EventSource',
    'navigator.serviceWorker',
    // An <img src> or a stylesheet injection is an outbound GET too. `dom.ts`
    // deliberately has no href/src helper, and this keeps it that way.
    'new Image',
  ];

  const others = sourceFiles.filter((file) => !file.endsWith(join('src', 'api.ts')));

  it('finds the modules it is meant to be checking', () => {
    expect(others.length).toBeGreaterThan(3);
    expect(sourceFiles.some((f) => f.endsWith(join('src', 'api.ts')))).toBe(true);
  });

  it.each(others)('%s makes no network call', (file) => {
    const source = code(file);
    for (const sink of EGRESS) {
      expect({ file, sink, found: source.includes(sink) }).toEqual({ file, sink, found: false });
    }
  });

  it('api.ts really is the module that calls fetch (so the fence is not vacuous)', () => {
    expect(code(join(SRC, 'api.ts'))).toContain('fetch(');
  });

  it('nothing logs, because a log is an exfiltration channel too', () => {
    // A `console.log(session)` survives review far more easily than a fetch —
    // and in an extension the console is readable by anything with devtools
    // access and shipped by any error reporter. There is no logger here at all.
    for (const file of sourceFiles) {
      expect({ file, logs: /\bconsole\s*\./.test(code(file)) }).toEqual({ file, logs: false });
    }
  });
});

describe('the extension holds no credential of the platform’s', () => {
  it('mentions no internal service credential', () => {
    for (const file of sourceFiles) {
      expect({ file, mentions: /_INTERNAL_TOKEN/.test(code(file)) }).toEqual({
        file,
        mentions: false,
      });
    }
  });
});
