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
    //
    // @estate/vault-crypto is deliberately a DEV dependency and not a runtime
    // one, which is a statement about this Node process rather than a
    // technicality: the edge never imports it. Its browser build is copied into
    // `public/lib` at build time and served as static files, so it is a build
    // input here and a runtime dependency of the BROWSER — a distinction this
    // list would erase if the package were promoted.
    expect(Object.keys(packageJson.dependencies)).toEqual(['zod']);
    expect(Object.keys(packageJson.devDependencies)).toContain('@estate/vault-crypto');
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
   * NOTHING IS STRIPPED FIRST, and that is the point.
   *
   * An earlier revision removed HTML comments before asserting, so that comment
   * PROSE could not trip the check. CodeQL flagged it (high,
   * js/incomplete-multi-character-sanitization) because a single-pass
   * `replace(/<!--[\s\S]*?-->/g, '')` is incomplete — surrounding text can
   * re-form a comment opener once an inner comment is removed.
   *
   * The textbook fix is to loop until the string stops changing. HERE THAT
   * WOULD HAVE BEEN WORSE, and measurably so: given
   * `<!<!-- -->-- <script>evil()</script> <!<!-- -->-- -->`, one pass leaves the
   * `<script>` visible and the assertion CATCHES it, while the loop strips the
   * whole thing to `''` and the assertion sees nothing. CodeQL's rule is aimed
   * at SANITIZERS, whose output gets rendered; this is a DETECTOR, and for a
   * detector the dangerous direction is the opposite one. A "fix" that makes a
   * security fence blind to what it exists to find is not a fix.
   *
   * So the assertions run on the raw bytes. The cost is that a future comment
   * mentioning a script tag fails this test — a FALSE POSITIVE, which someone
   * looks at and resolves, rather than a false negative, which nobody sees.
   * That is the safe direction for a fence, and it is why there is no
   * sanitization step left for CodeQL to flag.
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

/**
 * THE ZONE B SURFACE ON THIS ORIGIN IS ONE PROJECTED READ (M15 PR3).
 *
 * Emergency access needs contact NAMES, so profile became reachable from the
 * vault origin. The safe version of that is a handler which parses profile's
 * answer and keeps three fields; the unsafe version is a proxy entry, which
 * would put profile's whole owner-facing surface — relationships, family,
 * notes, the profile row itself — one path segment away from Zone A.
 *
 * The realistic regression is somebody adding `{ prefix: '/api/profile/',
 * upstream: 'profile', … }` for a screen that wants one more field. This
 * refuses that shape rather than trusting the review that let it in.
 */
describe('profile is reachable only through the projection', () => {
  const server = code(join(SRC, 'server.ts'));

  it('finds the route table it is meant to be checking', () => {
    expect(server).toContain('PROXY_ROUTES');
    expect(server).toContain("upstream: 'vault'");
  });

  /**
   * The route table's own text, sliced on CODE.
   *
   * The first version of this anchored its end on a comment — and `server` is
   * `code()`, which strips comments, so `indexOf` returned -1, `slice(start,
   * -1)` ran to the end of the file, and the fence scanned everything rather
   * than the table it is named for. It still went red under mutation, which is
   * why it survived: a scan that is too WIDE catches the planted defect and
   * hides the fact that it is not testing the stated layer. The M15 review
   * found it; the anchor is the array's own closing bracket now.
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
    expect(table).toContain("upstream: 'vault'");
    expect(table).toContain("upstream: 'identity'");
    // Proof of scoping: the projected profile handler lives BELOW the table and
    // must not be inside the slice, or the check below would be meaningless.
    expect(table).not.toContain('handleGranteeCandidates');
    expect(table).not.toContain('projectGranteeCandidates');
    expect(table.length).toBeLessThan(server.length / 2);
  });

  it('declares no profile entry in the proxy allowlist', () => {
    // The `upstream` union still NAMES profile, because the projected handler
    // is a profile caller. What must not exist is a routed one.
    expect(proxyRouteTable()).not.toContain("upstream: 'profile'");
  });

  it('reaches profile from exactly one place, and projects what comes back', () => {
    const reads = server.split("path: '/v1/contacts").length - 1;
    expect(reads).toBe(1);
    expect(server).toContain('projectGranteeCandidates(parsed)');
  });
});

/**
 * THE SINGLE-USE SPELLINGS THIS REPO HAS ACTUALLY WRITTEN ARE ABSENT (M27 PR3a).
 *
 * Release stopped being single-use when the guard began admitting
 * `status IN ('waiting','released')`, and FOUR sentences in this origin's
 * source went on saying otherwise. One was the warning on the confirmation
 * screen — the last thing somebody reads before acting in an emergency. One
 * was the capitalised heading on `releaseAndRecover` itself, the module's only
 * description of the function that performs the collection.
 *
 * THE HEADING IS WHY THIS DOCSTRING NO LONGER CLAIMS COMPLETENESS. The first
 * draft of this block was titled "no sentence on this origin claims the
 * arrangement is single-use", which is a claim far wider than eight hand-typed
 * strings can support — and it was wrong on its first run in exactly that gap:
 * the heading said `spends the escrow` while the list banned `spent the
 * escrow`, and `can only succeed once per arrangement` while the list banned
 * `can be done once`. A fence whose input is narrower than its claim goes
 * green for the same reason it is wrong. So the claim is now the narrow, true
 * one — these spellings are absent from this corpus — and the bound is stated
 * below rather than implied away.
 *
 * THE STATED BOUND: this list is HAND-WRITTEN and cannot be derived, because
 * nothing in the tree enumerates the ways English can assert single use. A
 * fifth wording would pass. What the fence buys is that a spelling this repo
 * has already written cannot come back, which is the failure that actually
 * happened, three times, in one PR. The complement — a NEW wording — is
 * answered by reading the screens, and `screens-emergency.spec.ts` asserts the
 * rendered confirmation copy for that reason.
 *
 * COMMENTS ARE IN THE CORPUS and the text is DE-WRAPPED before searching. Both
 * are the M24 wording-fence lesson, in the two directions it cuts. That fence's
 * first draft EXEMPTED comments so its own documentation could quote the bad
 * strings, and the exemption was wrong about block-comment continuation lines —
 * so nothing here is exempt, and the comments explaining this history DESCRIBE
 * these sentences rather than quoting them. De-wrapping is the other direction:
 * a review of this PR found a banned phrase quoted across a line break, green
 * only because of where the line happened to end, and one re-flow away from
 * red. Joining continuation lines can only make the search find MORE, never
 * less, which is the safe direction for a filter to err in.
 *
 * DELIBERATELY NOT BANNED: `one-shot`. It is an engineering term these comments
 * need to describe what changed, and no user-facing sentence would contain it —
 * banning it would make the history unwritable to catch a string that cannot
 * reach a screen.
 */
describe('the single-use spellings this repo has written are absent from src', () => {
  const BANNED: readonly string[] = [
    'spends the arrangement',
    'spend the arrangement',
    'spends the escrow',
    'spent the escrow',
    'can be done once',
    'succeed once',
    'used a second time',
    'cannot be used again',
    'is now spent',
    'only chance',
  ];

  /** Continuation lines joined, so a line break cannot hide or create a hit. */
  const flatten = (raw: string): string =>
    raw.replace(/\s*\n\s*(?:\/\/|\*)?\s*/g, ' ').toLowerCase();

  it.each(BANNED)('no source file says %p', (phrase) => {
    const offenders = allSourceFiles.filter((file) =>
      flatten(readFileSync(file, 'utf8')).includes(phrase),
    );
    expect(offenders).toEqual([]);
  });

  it('POSITIVE CONTROL: the corpus is real and this search does find things', () => {
    // Without this, a corpus that had silently become empty — a moved `src`, a
    // walk that stopped descending — passes every assertion above by finding
    // nothing, which is indistinguishable from finding nothing wrong.
    expect(allSourceFiles.length).toBeGreaterThan(5);
    const hits = allSourceFiles.filter((file) =>
      flatten(readFileSync(file, 'utf8')).includes('emergency'),
    );
    expect(hits.length).toBeGreaterThan(0);
  });

  it('POSITIVE CONTROL: de-wrapping finds a phrase broken across lines', () => {
    // The specific defect this de-wrap exists for, proved on a fixture rather
    // than trusted: a banned phrase split by a comment continuation is found.
    const wrapped = '// the old sentence said it is\n          // now spent, which was true then';
    expect(wrapped.toLowerCase().includes('is now spent')).toBe(false);
    expect(flatten(wrapped).includes('is now spent')).toBe(true);
  });
});
