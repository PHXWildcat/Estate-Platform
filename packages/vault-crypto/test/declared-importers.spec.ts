/**
 * WHO MAY IMPORT ZONE A's CRYPTO, declared as data (M16).
 *
 * `zero-dependency.spec.ts` beside this one fences what this package may reach
 * OUTWARD. This is the other direction — who may reach IN — and until M16 it did
 * not exist. M15 PR1 shipped seven fences for the vault origin and this was not
 * among them, which was tolerable while there was exactly one browser consumer
 * and one server consumer, and stops being tolerable the moment a second client
 * of the SRP/2SKD protocol arrives.
 *
 * WHY A TABLE RATHER THAN A REVIEW HABIT. This package holds the only code that
 * can derive a vault key, and its audit surface is the argument for everything
 * in docs/03 §4 TB6: no dependency tree, no bundler, what ships is what a
 * reviewer reads. That argument is about the code, and it says nothing about how
 * many places load it. A fifth importer added quietly is a fifth place a Zone A
 * key can be constructed, and the diff that adds it looks like one line in a
 * package.json. The credential-graph precedent applies verbatim: state the
 * permitted set as data, fail the build on drift, in BOTH directions.
 *
 * PR1 PROMISED THIS AND DID NOT SHIP IT. The decision log
 * (`docs/06-decision-log.md`, 2026-08-10) and `docs/04` both said the fence
 * "lands as data BEFORE that importer exists", and it did not — the same defect
 * PR1 opens by fixing, where migration 004 cited a spec pinning its CHECK to the
 * TypeScript union and no such spec existed. Recorded here rather than quietly
 * corrected, because a fence that a document claims and nobody wrote is worse
 * than one nobody claimed: the citation is what stops the next person looking.
 *
 * The mechanism is `readFileSync` over the tree — the zero-dependency-fence
 * precedent — so this suite creates no package edge and cannot be defeated by
 * how a consumer happens to be wired.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO = join(__dirname, '..', '..', '..');
const PACKAGE = '@estate/vault-crypto';

/**
 * The absolute path the BROWSER loads it by. `apps/vault-web` copies the ESM
 * build into its served tree and imports `/lib/vault-crypto/index.js`, so a
 * scan for the bare specifier alone would miss the one consumer that actually
 * ships this code to a user's device — the opposite of what this fence is for.
 */
const SERVED_PATH = '/lib/vault-crypto/';

/**
 * WHO MAY IMPORT IT, AND WHY. A reason per entry, because "which packages" is
 * answerable from the lockfile and "why each is allowed" is not.
 */
const VAULT_CRYPTO_IMPORTERS: Readonly<Record<string, string>> = {
  'apps/services/vault':
    'The SERVER half of SRP-6a. The service verifies a client proof and never ' +
    'derives, holds or unwraps anything that opens a vault — the package ships ' +
    'both roles precisely so one implementation backs both ends.',
  'apps/vault-web':
    'The isolated vault origin (docs/03 §6i). Loads the ESM build by absolute ' +
    'path from its own served tree, so no bare specifier reaches a browser and ' +
    'the CSP stays `script-src self` with no import map to admit.',
  'apps/vault-extension':
    'The browser extension (M16 PR2b). Loads the ESM build by absolute path ' +
    'from its OWN packaged root — MV3 forbids remotely hosted code, so these ' +
    'modules ship inside the signed artifact. Exactly one file imports it, ' +
    'the worker that holds the key, enforced by that package’s own fence.',
  'apps/e2e':
    'Drives the protocol end to end against the running stack. Test-only, and ' +
    'the reason the no-key-material-egress claim is checkable at all.',
};

/** Every workspace package directory, relative to the repo root. */
function workspacePackages(): string[] {
  const roots = ['packages', 'apps', join('apps', 'services')];
  const out: string[] = [];
  for (const root of roots) {
    const abs = join(REPO, root);
    if (!existsSync(abs)) continue;
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const rel = join(root, entry.name);
      if (existsSync(join(REPO, rel, 'package.json'))) out.push(rel);
    }
  }
  return [...new Set(out)].sort();
}

/** Comments name this package constantly — as a precedent, in prose. Strip them. */
function code(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (current: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'dist-esm') {
        continue;
      }
      if (entry.name === 'coverage' || entry.name === '.turbo' || entry.name === '.next') continue;
      const path = join(current, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (/\.(ts|tsx|mjs|js)$/.test(entry.name) && !path.includes(join('public', 'lib'))) {
        out.push(path);
      }
    }
  };
  walk(dir);
  return out;
}

/** Does this package REALLY reach the crypto — by manifest or by import? */
function reachesVaultCrypto(pkg: string): boolean {
  const manifest = JSON.parse(readFileSync(join(REPO, pkg, 'package.json'), 'utf8')) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  if (manifest.dependencies?.[PACKAGE] || manifest.devDependencies?.[PACKAGE]) {
    return true;
  }
  return filesUnder(join(REPO, pkg)).some((file) => {
    const source = code(readFileSync(file, 'utf8'));
    return source.includes(PACKAGE) || source.includes(SERVED_PATH);
  });
}

describe('who may import @estate/vault-crypto', () => {
  const packages = workspacePackages();

  it('finds the workspace it is meant to be checking', () => {
    // Anti-vacuity, the credential-graph lesson: a scan that silently enumerates
    // nothing passes every assertion below it.
    expect(packages.length).toBeGreaterThan(20);
    expect(packages).toContain('apps/services/vault');
    expect(packages).toContain('apps/vault-web');
  });

  it('every declared importer names a real package that really reaches it', () => {
    // The reverse direction matters as much: an entry left behind after a
    // consumer stops importing reads as a wider permitted set than is in force,
    // and the next person adding one copies the stale shape.
    for (const [pkg, reason] of Object.entries(VAULT_CRYPTO_IMPORTERS)) {
      expect({ pkg, exists: packages.includes(pkg) }).toEqual({ pkg, exists: true });
      expect({ pkg, reaches: reachesVaultCrypto(pkg) }).toEqual({ pkg, reaches: true });
      // A reason, not a placeholder. "Which packages" is answerable from the
      // lockfile; "why each is allowed" is the thing this table exists to hold.
      expect(reason.length).toBeGreaterThan(40);
    }
  });

  it('NO UNDECLARED PACKAGE reaches it', () => {
    for (const pkg of packages) {
      if (pkg === join('packages', 'vault-crypto')) continue; // itself
      if (VAULT_CRYPTO_IMPORTERS[pkg]) continue;
      expect({ pkg, reaches: reachesVaultCrypto(pkg) }).toEqual({ pkg, reaches: false });
    }
  });

  it('the browser consumer is counted by the path it actually loads', () => {
    // `apps/vault-web`'s client imports `/lib/vault-crypto/index.js`, not the
    // bare specifier — it is served from that origin's own tree. A fence that
    // only looked for `@estate/vault-crypto` would miss the one consumer that
    // ships this code to a user's device, which is the opposite of the point.
    const clientFiles = filesUnder(join(REPO, 'apps', 'vault-web', 'src', 'client'));
    const loadsByPath = clientFiles.some((file) =>
      code(readFileSync(file, 'utf8')).includes(SERVED_PATH),
    );
    expect(loadsByPath).toBe(true);
  });
});
