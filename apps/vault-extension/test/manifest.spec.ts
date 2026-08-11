/**
 * THE MANIFEST IS THE PERMISSION SET, PINNED AS DATA.
 *
 * docs/04's supply-chain decision for M16 names "minimum permissions pinned as
 * data" among the controls that work unattended, and this is that: the declared
 * literal below is the whole of what this artifact may do, and widening it
 * fails a test before it reaches a review. Chrome surfaces a permission
 * increase to the USER as a re-consent prompt on update — this makes it
 * surface to US first.
 *
 * EVERY ABSENCE HERE IS DELIBERATE, AND EACH ARRIVAL IS DATED. `offscreen`
 * came with PR2b, which needed somewhere for a key to live; `activeTab` comes
 * with PR3a, which needs the active tab's URL to decide what is saved for this
 * page. Still absent: `scripting` and `content_scripts` — the two that turn
 * "read the URL" into "run code in the page", and PR3b's deliberate act.
 *
 * The discipline is that each one is a reviewable increase rather than a line
 * nobody remembers adding, and that this file names the PR against every
 * absence so the next arrival has to edit a declaration.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(__dirname, '..');
const TEMPLATE = JSON.parse(readFileSync(join(ROOT, 'manifest.template.json'), 'utf8')) as Record<
  string,
  unknown
>;

/**
 * The permission set, as data. Changing this is the reviewable act.
 *
 * `offscreen` arrived in PR2b with the document it is for, which is exactly the
 * discipline: PR2a listed it among the keys that must NOT appear, naming the PR
 * that would introduce it, and this is that PR.
 *
 * `scripting` arrived in PR3b, and it is the largest single increase this
 * extension will take: it is what turns "read the active tab's URL" into "run
 * code in that page". It travels ALONE. `content_scripts` stays forbidden
 * below, because a declared content script is standing access to every matching
 * page on every load, whereas a one-shot `executeScript` at the moment of a
 * gesture leaves no channel a page can address; and `web_accessible_resources`
 * stays forbidden because it makes an extension resource addressable BY the
 * page, which is the direction §4 TB9 exists to close.
 */
const PERMISSIONS = ['storage', 'offscreen', 'activeTab', 'scripting'];

/** Keys that must NOT appear at all, each with the PR that would introduce it. */
const FORBIDDEN_KEYS = [
  // BOTH STAY FORBIDDEN THROUGH PR3b, which is the PR that was named against
  // them — the fill is a one-shot injection into a named frame, so neither is
  // needed and each would widen the surface in the direction TB9 closes.
  'content_scripts',
  'web_accessible_resources',
  'externally_connectable', // rejected outright (docs/04: the control is an absence)
  'declarative_net_request',
  'oauth2',
  'key',
];

describe('the manifest declares the minimum, and says so as data', () => {
  it('is Manifest V3', () => {
    expect(TEMPLATE['manifest_version']).toBe(3);
  });

  it('requests exactly the declared permissions', () => {
    expect(TEMPLATE['permissions']).toEqual(PERMISSIONS);
  });

  it('runs its service worker as a MODULE, and names only the one file', () => {
    // The service worker holds nothing — its only job is the offscreen
    // document's lifecycle (an MV3 worker is terminated in seconds and cannot
    // hold a key). `type: module` is what lets it use the same native ES
    // modules as everything else here, with no bundler.
    expect(TEMPLATE['background']).toEqual({
      service_worker: 'background.js',
      type: 'module',
    });
  });

  it('requests exactly ONE host, and it is the placeholder the build substitutes', () => {
    // One `host_permission`, one origin — docs/04's transport decision, and the
    // property `config.ts` relies on when it reads the origin back at runtime.
    expect(TEMPLATE['host_permissions']).toEqual(['__VAULT_ORIGIN__/*']);
  });

  it.each(FORBIDDEN_KEYS)('declares no %s', (key) => {
    expect(Object.keys(TEMPLATE)).not.toContain(key);
  });

  /**
   * `activeTab` ARRIVED IN PR3a, and it is the narrowest thing that could:
   * it grants the active tab's URL only at the moment the user clicks the
   * extension, and is revoked on navigation. Reading a URL is not running code
   * in a page — `scripting` is what would allow that, and it is still absent.
   */
  it('can run code in the active tab ONLY, and holds no standing page access', () => {
    /*
     * RENAMED IN PR3b, not relaxed. The previous case asserted the extension
     * "CANNOT run code in any page" and PR3b makes that false, so deleting the
     * assertion would have left a test NAME claiming a property the artifact no
     * longer has — the "a claim that outlived the fact" class this repo keeps
     * finding, and worse here because this case is the only place the page-
     * access boundary is written down.
     *
     * What survives the change is the real boundary: code runs only in a tab the
     * user has just invoked the extension on, and only for as long as that grant
     * lasts. There is no standing access to anything.
     */
    const serialized = JSON.stringify(TEMPLATE);
    expect(TEMPLATE['permissions']).toContain('activeTab');
    expect(TEMPLATE['permissions']).toContain('scripting');
    // `activeTab` is what bounds `scripting`: without a host permission it
    // grants nothing until the user acts, and it is revoked on navigation.
    // Measured in Chrome 151: the grant is the main frame's ORIGIN, host-exact.
    expect(serialized).not.toContain('<all_urls>');
    expect(serialized).not.toContain('http://*/');
    expect(serialized).not.toContain('https://*/');
    // Tab state generally, and the frame enumeration a fill does not need.
    expect(TEMPLATE['permissions']).not.toContain('tabs');
    expect(TEMPLATE['permissions']).not.toContain('webNavigation');
    // Host permissions stay exactly the vault origin — the extension's single
    // front door — and never a page it might fill. (Asserted in full above; the
    // point restated here is that `scripting` did NOT come with a page host.)
    expect(TEMPLATE['host_permissions']).toHaveLength(1);
  });
});

describe('the build bakes the origin, and only a real origin', () => {
  /**
   * Builds into a TEMP directory, never the package's own `dist`.
   *
   * These cases build with a TEST origin, so writing to `dist` would leave a
   * loadable extension addressing `vault.estate.test` behind every test run —
   * an artifact that looks built and silently points nowhere.
   */
  function build(origin: string, options: { omitEntry?: string } = {}): Record<string, unknown> {
    const out = mkdtempSync(join(tmpdir(), 'vault-ext-'));
    try {
      /*
       * The compiled entries would come from tsc in a real build. They are
       * stubbed here so the script's own packaging check RUNS rather than being
       * skipped in the temp directory — the check exists because a page the
       * manifest names but the package lacks is a runtime load failure that
       * names the manifest rather than the omission (the `web.Dockerfile`
       * lesson). `omitEntry` leaves one out, so the check is proved to fire.
       */
      for (const entry of ['main.js', 'offscreen.js', 'background.js']) {
        if (entry !== options.omitEntry) writeFileSync(join(out, entry), '');
      }
      execFileSync(process.execPath, [join(ROOT, 'scripts', 'build-package.mjs')], {
        cwd: ROOT,
        env: { ...process.env, VAULT_ORIGIN: origin, OUT_DIR: out },
        stdio: 'pipe',
      });
      return JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')) as Record<
        string,
        unknown
      >;
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }

  it('substitutes the configured origin into the host permission', () => {
    // The M8 PR5 lesson: a value baked into an artifact must be ASSERTED, not
    // assumed. The web image once shipped a rewrite pointing at itself because
    // nothing checked the baked value.
    const manifest = build('https://vault.estate.test');
    expect(manifest['host_permissions']).toEqual(['https://vault.estate.test/*']);
    expect(JSON.stringify(manifest)).not.toContain('__VAULT_ORIGIN__');
  });

  it.each(['main.js', 'offscreen.js', 'background.js'])(
    'refuses to package with %s missing',
    (entry) => {
      expect(() => build('https://vault.estate.test', { omitEntry: entry })).toThrow();
    },
  );

  it.each([
    ['not-a-url', 'not a URL'],
    ['https://*.estate.test', 'wildcard host'],
    ['https://vault.estate.test/path', 'carries a path'],
  ])('refuses %s (%s)', (origin) => {
    expect(() => build(origin)).toThrow();
  });
});
