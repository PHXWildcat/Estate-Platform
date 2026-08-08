/**
 * Copy @estate/vault-crypto's BROWSER build into the served tree (M15 PR2).
 *
 * The client imports it by ABSOLUTE PATH — `/lib/vault-crypto/index.js`, served
 * by this origin — rather than through a bare specifier resolved by an inline
 * import map. That choice is what lets the origin's CSP stay `script-src 'self'`
 * with no `'sha256-…'` and no `'unsafe-inline'` for the life of the app: there
 * is no inline script to admit, because there is no import map.
 *
 * A COPY rather than a second static root in the server, deliberately. The
 * static handler is the one piece of this edge that turns a URL into a file
 * path, and its safety argument (documented in server.ts) rests on there being
 * exactly one root to reason about. Adding a second would double that argument
 * for the sake of avoiding a file copy.
 *
 * Node's `fs.cp` rather than a shell `cp -r`: this runs on the maintainer's
 * Windows workstation as well as in the Linux image build.
 */
import { cp, rm, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = join(here, '..', '..', '..', 'packages', 'vault-crypto', 'dist-esm');
const destination = join(here, '..', 'public', 'lib', 'vault-crypto');

// Replace rather than merge: a module deleted upstream must not survive here as
// a file the browser can still load.
await rm(destination, { recursive: true, force: true });
await cp(source, destination, { recursive: true });

const copied = await readdir(destination);
if (!copied.includes('index.js')) {
  // Fail loudly. A silently empty directory would mean the vault client 404s
  // its own crypto at runtime — a shell that loads and a page that never works,
  // which is the class the 2026-08-06 web.Dockerfile defect belonged to.
  throw new Error(`vault-crypto browser build missing from ${source} — run its build first`);
}
process.stdout.write(`copied ${copied.length} vault-crypto modules into public/lib\n`);
