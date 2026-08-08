/**
 * THE VAULT ORIGIN'S FENCES (M15 PR1).
 *
 * docs/03 rates client-side compromise of this origin Critical (TB6, risk #4),
 * and the realistic regression is never a deliberate weakening — it is a second
 * surface importing vault crypto, a convenience dependency, a `console.log`
 * added while debugging, or one `innerHTML` in a hurry. Prose does not catch
 * any of those. These do.
 *
 * Every one is MUTATION-TESTED red before green; a fence that has never failed
 * has never been tested. The mechanism throughout is `readFileSync` over the
 * source — the @estate/vault-crypto zero-dependency-fence precedent, which
 * creates no package edge and therefore cannot be defeated by how a module
 * happens to be wired.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import packageJson from '../package.json';

const ROOT = join(__dirname, '..');
const CLIENT = join(ROOT, 'src', 'client');
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

const clientFiles = filesUnder(CLIENT);
const allSourceFiles = filesUnder(SRC);

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

describe('the browser client has no dependency tree', () => {
  it('finds the files it is meant to be checking', () => {
    // Never pass vacuously — the credential-graph anti-drop lesson.
    expect(clientFiles.length).toBeGreaterThan(2);
  });

  it.each(clientFiles)('%s imports only relative paths or the vault crypto package', (file) => {
    for (const specifier of importSpecifiers(file)) {
      // Relative (with an explicit .js, since these are native ES modules), or
      // the ONE workspace package this origin is allowed to load — served from
      // this origin by absolute path so no bare specifier ever reaches a
      // browser, and no import map has to be admitted by the CSP.
      const permitted =
        specifier.startsWith('./') ||
        specifier.startsWith('../') ||
        specifier === '/lib/vault-crypto/index.js';
      expect({ file, specifier, permitted }).toEqual({ file, specifier, permitted: true });
    }
  });

  it('relative client imports carry an explicit .js, or the browser cannot resolve them', () => {
    for (const file of clientFiles) {
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

  it('the package declares no runtime dependency beyond the edge’s zod', () => {
    // The EDGE may use zod, like every other service's config. The CLIENT's
    // dependency surface is enforced above, by import, because that is what
    // actually ships to the browser.
    expect(Object.keys(packageJson.dependencies)).toEqual(['zod']);
  });
});

describe('no HTML sinks anywhere on this origin', () => {
  /**
   * ZERO declared exemptions, and that is the difference from the main app.
   * `apps/web` has exactly one (its theme script) and says so; this origin has
   * none, because `trusted-types 'none'` means the browser would throw on any
   * of these anyway — the fence catches the mistake at build time instead of
   * shipping a page that breaks at runtime.
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

  it.each(allSourceFiles)('%s contains no HTML/script sink', (file) => {
    const source = code(file);
    for (const sink of SINKS) {
      expect({ file, sink, found: source.includes(sink) }).toEqual({ file, sink, found: false });
    }
  });

  it('the served shell has no inline script and no inline style', () => {
    // The CSP admits neither. Asserting it here means a hand edit to the static
    // HTML fails a test rather than a page.
    const html = readFileSync(join(ROOT, 'public', 'index.html'), 'utf8');
    const withoutComments = html.replace(/<!--[\s\S]*?-->/g, '');
    expect(withoutComments).not.toMatch(/<script(?![^>]*\ssrc=)/i);
    expect(withoutComments).not.toMatch(/\sstyle=/i);
    expect(withoutComments).not.toMatch(/<script[^>]*type=["']importmap["']/i);
  });
});

describe('key material cannot leave through a call site that does not exist', () => {
  /**
   * THE CENTRAL CLAIM OF THE MILESTONE, made checkable.
   *
   * Nothing derived from the vault password or the Secret Key may leave the
   * device. `api.ts` is the only module that may reach the network, so there is
   * exactly ONE call site to audit rather than a property to re-argue every
   * time a screen is added. The CSP's `connect-src 'self'` is the second layer
   * under this one.
   */
  const EGRESS = [
    'fetch(',
    'XMLHttpRequest',
    'sendBeacon',
    'new WebSocket',
    'EventSource',
    'navigator.serviceWorker',
    // An <img src> or a stylesheet injection is an outbound GET too. The DOM
    // helper deliberately has no href/src attribute, and this keeps it that way.
    'new Image',
  ];

  const others = clientFiles.filter((file) => !file.endsWith(join('client', 'api.ts')));

  it('finds the client modules it is meant to be checking', () => {
    expect(others.length).toBeGreaterThan(1);
    expect(clientFiles.some((f) => f.endsWith(join('client', 'api.ts')))).toBe(true);
  });

  it.each(others)('%s makes no network call', (file) => {
    const source = code(file);
    for (const sink of EGRESS) {
      expect({ file, sink, found: source.includes(sink) }).toEqual({ file, sink, found: false });
    }
  });

  it('api.ts really is the module that calls fetch (so the fence is not vacuous)', () => {
    expect(code(join(CLIENT, 'api.ts'))).toContain('fetch(');
  });

  it('no client module logs, because a log is an exfiltration channel too', () => {
    // A `console.log(masterKey)` survives review far more easily than a fetch.
    // Browsers keep console history, extensions read it, and error reporters
    // ship it. There is no logger on this origin at all.
    for (const file of clientFiles) {
      expect({ file, logs: /\bconsole\s*\./.test(code(file)) }).toEqual({ file, logs: false });
    }
  });
});

describe('the edge holds no credential and no key', () => {
  it('mentions no internal service credential', () => {
    // The runtime half lives in `test/config.spec.ts` (credentialsHeldIn), the
    // ai-assistant precedent. This is the source half: an `*_INTERNAL_TOKEN`
    // must not appear here even as a string.
    for (const file of allSourceFiles) {
      expect({ file, mentions: /_INTERNAL_TOKEN/.test(code(file)) }).toEqual({
        file,
        mentions: false,
      });
    }
  });
});
