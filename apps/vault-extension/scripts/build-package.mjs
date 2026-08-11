/**
 * Assemble the loadable extension: the compiled ES modules (already in `dist`
 * from tsc), the static shell, and a manifest with the vault origin in it.
 *
 * THE ORIGIN IS A BUILD INPUT, exactly like `web`'s `VAULT_ORIGIN` — and for
 * the same reason it had to be there: a `host_permissions` entry is a literal
 * in a JSON file that the browser reads before any code runs, so it cannot come
 * from runtime configuration. What M8 PR5 taught is that a baked value must
 * then be ASSERTED rather than assumed, which `test/manifest.spec.ts` does.
 *
 * There is deliberately no SECOND copy of the origin in the source: `config.ts`
 * reads it back out of the manifest at runtime, so this script is the only
 * place it is written and there is nothing for it to drift against.
 */
import { copyFile, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
/*
 * `OUT_DIR` exists for the manifest test, and its absence would be a real
 * footgun rather than an inconvenience: that test builds with a TEST origin, so
 * writing into the package's own `dist` would leave a loadable extension
 * pointing at `vault.estate.test` behind every `pnpm test` — an artifact that
 * looks built and silently addresses nowhere.
 */
const dist = process.env.OUT_DIR ?? join(root, 'dist');

/**
 * The dev stack's vault origin. A default rather than a required variable
 * because the common case is a developer loading this unpacked against the
 * local stack, and `PLAID_MODE`'s lesson applies: a build that refuses to run
 * without configuration nobody has yet is a build nobody runs.
 */
const DEFAULT_ORIGIN = 'http://vault.localhost:3010';

const origin = (process.env.VAULT_ORIGIN ?? DEFAULT_ORIGIN).replace(/\/$/, '');

// Parsed, not interpolated. A malformed value would otherwise become a
// malformed match pattern, which Chrome rejects at load with an error that
// names the manifest rather than the mistake.
let parsed;
try {
  parsed = new URL(origin);
} catch {
  throw new Error(`VAULT_ORIGIN is not a URL: ${origin}`);
}
if (parsed.origin !== origin || parsed.hostname.includes('*')) {
  throw new Error(`VAULT_ORIGIN must be an exact origin, got: ${origin}`);
}

const template = await readFile(join(root, 'manifest.template.json'), 'utf8');
const manifest = template.replaceAll('__VAULT_ORIGIN__', origin);
if (manifest.includes('__VAULT_ORIGIN__')) {
  throw new Error('manifest placeholder survived substitution');
}
// Parsed before it is written: a manifest that is not JSON fails here, in a
// build, rather than in a browser with "Manifest is not valid JSON".
JSON.parse(manifest);

await mkdir(dist, { recursive: true });
await writeFile(join(dist, 'manifest.json'), manifest);

const publicDir = join(root, 'public');
const statics = await readdir(publicDir);
await Promise.all(statics.map((name) => copyFile(join(publicDir, name), join(dist, name))));

process.stdout.write(
  `vault-extension packaged for ${origin} (${String(statics.length)} static files)\n`,
);
