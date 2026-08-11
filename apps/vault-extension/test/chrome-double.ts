/**
 * A stand-in for the four extension-platform members this package uses.
 *
 * CI cannot load a packed extension, so the platform is doubled and the
 * TRANSPORT is proven live at the edge instead (see the PR's verification
 * notes). The double is deliberately faithful about the two things that have
 * bitten this repo before: `storage.local` round-trips through a structured
 * clone, so a value that could not survive one fails here rather than in a
 * browser, and `getManifest` returns the REAL manifest template with the same
 * substitution the build performs, so a test cannot pass against a manifest
 * shape the build does not produce.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const TEST_ORIGIN = 'https://vault.estate.test';

const TEMPLATE = readFileSync(join(__dirname, '..', 'manifest.template.json'), 'utf8');

export interface ChromeDouble {
  store: Map<string, unknown>;
  setManifest(manifest: unknown): void;
}

export function installChromeDouble(origin = TEST_ORIGIN): ChromeDouble {
  const store = new Map<string, unknown>();
  let manifest: unknown = JSON.parse(TEMPLATE.replaceAll('__VAULT_ORIGIN__', origin));

  const double = {
    storage: {
      local: {
        get: (key: string): Promise<Record<string, unknown>> =>
          Promise.resolve(store.has(key) ? { [key]: structuredClone(store.get(key)) } : {}),
        set: (items: Record<string, unknown>): Promise<void> => {
          for (const [key, value] of Object.entries(items)) {
            // Structured clone, like the real thing: a value the platform could
            // not persist must fail in the suite, not in someone's browser.
            store.set(key, structuredClone(value));
          }
          return Promise.resolve();
        },
        remove: (key: string): Promise<void> => {
          store.delete(key);
          return Promise.resolve();
        },
      },
    },
    runtime: { getManifest: (): unknown => manifest },
  };

  (globalThis as { chrome?: unknown }).chrome = double;
  return {
    store,
    setManifest: (next: unknown) => {
      manifest = next;
    },
  };
}

export function clearChromeDouble(): void {
  delete (globalThis as { chrome?: unknown }).chrome;
}
