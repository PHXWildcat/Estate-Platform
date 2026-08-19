/**
 * THE OPERATOR ORIGIN'S FENCES (M21 PR3a).
 *
 * docs/03 §4 TB7 is the trust boundary a platform operator crosses, and the
 * realistic regression on this origin is never a deliberate weakening — it is
 * one more allowlist entry added for a screen that wants one more field, a
 * convenience dependency, a `console.log` left in while debugging, or one
 * `innerHTML` in a hurry. Prose does not catch any of those. These do.
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
const edgeFiles = allSourceFiles.filter((file) => !file.startsWith(CLIENT + '/'));

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
    expect(edgeFiles.length).toBeGreaterThan(3);
  });

  it.each(clientFiles)('%s imports only relative paths', (file) => {
    for (const specifier of importSpecifiers(file)) {
      // RELATIVE ONLY, with an explicit .js since these are native ES modules.
      // The vault origin permits one absolute path because it serves
      // @estate/vault-crypto from its own tree; this origin serves nothing of
      // the kind, so the permitted set is smaller and stays that way.
      const permitted = specifier.startsWith('./') || specifier.startsWith('../');
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

describe('the DOM helper has no URL attribute, and one place has', () => {
  /**
   * `el` sets whatever key it is handed, so what keeps a URL out of the DOM
   * helper is the TYPE — and a runtime test cannot see a type. This is the
   * layer that can: `Attrs` is the declared attribute surface, and `href`/`src`
   * are absent from it deliberately.
   *
   * Why it matters: an `<img src>` or an injected stylesheet is an outbound GET,
   * which would be a second egress path on an origin whose whole claim is that
   * `api.ts` is the only one. The single legitimate URL on this origin is the
   * "back to Estate" link, built in `app.ts` over a value the edge already
   * validated as a URL.
   */
  const dom = code(join(CLIENT, 'dom.ts'));

  function attrsInterface(): string {
    const start = dom.indexOf('export interface Attrs');
    expect(start).toBeGreaterThanOrEqual(0);
    const end = dom.indexOf('\n}', start);
    expect(end).toBeGreaterThan(start);
    return dom.slice(start, end);
  }

  it('slices the interface and nothing else', () => {
    const attrs = attrsInterface();
    expect(attrs).toContain('readonly class?');
    // Proof of scoping: `el` lives below and must not be inside the slice.
    expect(attrs).not.toContain('document.createElement');
    expect(attrs.length).toBeLessThan(dom.length / 2);
  });

  it.each(['href', 'src', 'srcdoc', 'action', 'formaction', 'style'])(
    'declares no %s attribute',
    (attribute) => {
      expect(attrsInterface()).not.toContain(attribute);
    },
  );

  it('names setAttribute in exactly one module, and a URL in exactly one other', () => {
    const setters = clientFiles.filter((file) => code(file).includes('setAttribute'));
    expect(setters.map((f) => f.slice(CLIENT.length + 1))).toEqual(['app.ts', 'dom.ts']);
    // `app.ts`'s single use is the link, over the origin the edge validated.
    expect(code(join(CLIENT, 'app.ts')).match(/setAttribute/g)).toHaveLength(1);
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

  /**
   * NOTHING IS STRIPPED FIRST, and that is the point — the vault origin's own
   * note on this, which CodeQL flagged and which was answered rather than
   * "fixed": a single-pass comment stripper is incomplete for a SANITIZER,
   * whose output is rendered, and the incompleteness runs the SAFE way for a
   * DETECTOR, whose failure to see something is the only harm. Looping until
   * the string stops changing would make this fence blind to exactly what it
   * exists to find. The cost is a false positive if a future comment mentions a
   * script tag — which somebody looks at, rather than a false negative, which
   * nobody sees.
   */
  it('the served shell has no inline script and no inline style', () => {
    // The CSP admits neither. Asserting it here means a hand edit to the static
    // HTML fails a test rather than a page.
    const html = readFileSync(join(ROOT, 'public', 'index.html'), 'utf8');
    expect(html).not.toMatch(/<script(?![^>]*\ssrc=)/i);
    expect(html).not.toMatch(/\sstyle=/i);
    expect(html).not.toMatch(/<script[^>]*type=["']importmap["']/i);
  });
});

describe('estate content leaves through one call site or none', () => {
  /**
   * On the vault origin this fence makes a claim about KEY MATERIAL. Here it
   * makes one about the case detail an operator reads before they approve
   * something: `api.ts` is the only module that may reach the network, so there
   * is exactly ONE call site to audit rather than a property to re-argue every
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
    // A console line survives review far more easily than a fetch. Browsers
    // keep console history, extensions read it, and error reporters ship it.
    // There is no logger on this origin at all — and what would land in one
    // here is a case id, which names somebody's death.
    for (const file of clientFiles) {
      expect({ file, logs: /\bconsole\s*\./.test(code(file)) }).toEqual({ file, logs: false });
    }
  });
});

describe('the edge holds no credential', () => {
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

/**
 * THE ALLOWLIST IS THE SURFACE (M21 PR3a).
 *
 * A proxy that forwards whatever path it is given is an SSRF primitive carrying
 * a live bearer, so this edge routes exact paths to one upstream. Two
 * regressions are worth refusing by shape rather than by review.
 *
 * FIRST, a TREE. `startsWith('/api/auth/logout')` also matches
 * `/api/auth/logout/refresh`, identity's unauthenticated refresh-token
 * revocation route; `/api/auth/` as a prefix would reach `handoff`, and this
 * edge must not help an operator session mint another credential.
 *
 * SECOND, a SECOND UPSTREAM added for a screen. M21 PR3b adds settlement, and
 * it lands in the same change as the screens that call it — that is the point
 * of this fence failing now rather than approving in advance.
 */
describe('the proxy allowlist reaches identity, exactly and only', () => {
  const server = code(join(SRC, 'server.ts'));

  it('finds the route table it is meant to be checking', () => {
    expect(server).toContain('const PROXY_ROUTES');
    expect(server).toContain("upstream: 'identity'");
  });

  /**
   * The route table's own text, sliced on CODE.
   *
   * Anchored on the array's own closing bracket, never on a comment: `server`
   * is `code()`, which strips comments, so a comment anchor makes `indexOf`
   * return -1 and the slice run to the end of the file — a scan too WIDE still
   * catches a planted defect and hides that it is not testing the stated layer.
   * The M15 review found exactly that in the vault origin's copy.
   */
  function proxyRouteTable(): string {
    const start = server.indexOf('const PROXY_ROUTES');
    expect(start).toBeGreaterThanOrEqual(0);
    const end = server.indexOf('\n];', start);
    expect(end).toBeGreaterThan(start);
    return server.slice(start, end);
  }

  it('slices the route table and nothing else (so the scan is really scoped)', () => {
    const table = proxyRouteTable();
    expect(table).toContain("upstream: 'identity'");
    // Proof of scoping: the handlers live BELOW the table and must not be
    // inside the slice, or every check below would be meaningless.
    expect(table).not.toContain('handleProxy');
    expect(table).not.toContain('createOperatorWebServer');
    expect(table.length).toBeLessThan(server.length / 2);
  });

  it('routes to identity and to no other upstream', () => {
    const table = proxyRouteTable();
    for (const upstream of ['vault', 'profile', 'settlement', 'assets', 'documents']) {
      expect({ upstream, routed: table.includes(`upstream: '${upstream}'`) }).toEqual({
        upstream,
        routed: false,
      });
    }
  });

  it('names exactly the three routes an operator session is admitted to', () => {
    const table = proxyRouteTable();
    const paths = [...table.matchAll(/path: '([^']+)'/g)].map((m) => m[1]);
    expect(paths).toEqual(['/api/auth/session', '/api/auth/stepup', '/api/auth/logout']);
  });

  it('matches paths EXACTLY, with no prefix or tree entry anywhere in the table', () => {
    const table = proxyRouteTable();
    expect(table).not.toContain('prefix');
    expect(table).not.toContain('tree');
    // And the matcher itself: a `startsWith` would make every entry a tree
    // regardless of what the table says.
    const matcher = server.slice(server.indexOf('PROXY_ROUTES.find'));
    expect(matcher.slice(0, 120)).toContain('r.path === pathname');
    expect(matcher.slice(0, 120)).not.toContain('startsWith');
  });

  it('READS ONE CREDENTIAL FROM ONE PLACE — no bearer header path exists', () => {
    /*
     * The vault edge prefers `Authorization: Bearer` over its cookie, and that
     * exists for exactly one caller: the browser extension, which lives on
     * `chrome-extension://…` and can never receive a cookie this origin sets.
     * There is no extension on this origin. Adding the bearer path here would
     * be adding a way to drive an operator console from something other than a
     * browser, which is a design decision rather than a convenience — so it
     * fails a test rather than passing a review.
     *
     * `authorization` appears exactly once in this package, in `upstream.ts`,
     * where the edge SETS it on the way out. Reading one is what must not
     * happen.
     */
    expect(server).not.toContain('bearerFrom');
    expect(server).not.toMatch(/headers\[['"]authorization['"]\]/);
    for (const file of edgeFiles) {
      expect({ file, reads: /req\.headers\[['"]authorization['"]\]/.test(code(file)) }).toEqual({
        file,
        reads: false,
      });
    }
    // Anti-vacuity: the edge really does present one upstream, so the absence
    // above is a fact about the READ path rather than about the whole package.
    expect(code(join(SRC, 'upstream.ts'))).toContain('authorization');
  });

  it('has no pass-through table, because nothing here is credential-free but arrival', () => {
    // The vault edge carries two unauthenticated identity routes for the
    // extension: pairing redemption, and refresh. Neither has a counterpart
    // here — an operator session HAS NO REFRESH TOKEN AT ALL, since the handoff
    // ceremony writes the digest of a value it discards in the same expression.
    expect(server).not.toContain('PASS_THROUGH_ROUTES');
    expect(server).not.toContain('passThrough');
    expect(code(join(SRC, 'upstream.ts'))).not.toContain('passThrough');
  });
});
