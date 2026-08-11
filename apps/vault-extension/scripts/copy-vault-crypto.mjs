/**
 * Vendor `@estate/vault-crypto`'s BROWSER build into the packaged extension.
 *
 * MV3 FORBIDS REMOTELY HOSTED CODE, so unlike the vault origin — which serves
 * these modules from its own tree — the extension must carry them. Everything
 * that executes is inside the signed artifact, which is also the property
 * docs/03 §4 TB9 leans on: what ships is exactly what a reviewer reads.
 *
 * Copied, not bundled and not re-compiled. `packages/vault-crypto` emits the
 * same sources a second way (`tsconfig.esm.json`) precisely so a browser can
 * load them as written, and putting a bundler on the one dependency-free
 * package that holds Zone A key derivation would undo the argument for it.
 *
 * The offscreen document imports `/lib/vault-crypto/index.js` — a leading slash
 * resolves against the EXTENSION's own root (`chrome-extension://<id>/lib/…`),
 * so it is the same specifier `vault-web` uses and the same `paths` mapping
 * gives it types. No bare specifier ever reaches the browser.
 */
import { cp, mkdir, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = join(here, '..', '..', '..', 'packages', 'vault-crypto', 'dist-esm');
const destination = join(process.env.OUT_DIR ?? join(here, '..', 'dist'), 'lib', 'vault-crypto');

let modules;
try {
  modules = (await readdir(source)).filter((name) => name.endsWith('.js'));
} catch {
  throw new Error(`vault-crypto browser build missing from ${source} — run its build first`);
}
if (modules.length === 0) {
  throw new Error(`vault-crypto browser build at ${source} contains no modules`);
}

await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true });

process.stdout.write(`copied ${String(modules.length)} vault-crypto modules into lib/\n`);
