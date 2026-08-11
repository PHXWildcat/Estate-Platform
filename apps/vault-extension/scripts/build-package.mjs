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
 * IT IS WRITTEN TWICE, into the manifest and into `origin.js`, because an
 * offscreen document cannot read the manifest back (measured in Chrome 151:
 * it gets `chrome.runtime`'s messaging surface and nothing else), and the key
 * holder lives in one. Two places holding one value is a drift risk, so it is
 * CHECKED rather than trusted — `test/manifest.spec.ts` builds a real package
 * and asserts the two agree.
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

/*
 * Every page the manifest names must exist in the package, or Chrome fails the
 * load with an error naming the manifest rather than the omission — the
 * `web.Dockerfile` lesson (2026-08-06), where a file the build silently did not
 * copy became a runtime 404 nothing checked for.
 */
const required = [
  'popup.html',
  'offscreen.html',
  'main.js',
  'offscreen.js',
  'background.js',
  // The generated origin. Missing it would otherwise surface as an ENOENT from
  // the substitution below, naming a path instead of the omission.
  'origin.js',
];
const present = new Set(await readdir(dist));
const missing = required.filter((name) => !present.has(name));
if (missing.length > 0) {
  throw new Error(`packaged extension is missing: ${missing.join(', ')}`);
}

/*
 * The compiled `origin.js` carries the dev default from source; the packaged one
 * carries whatever this build was given.
 *
 * THE RESULT IS PARSED BACK, NOT SEARCHED FOR. The first version asserted with
 * `text.includes(origin)`, which CodeQL flagged as incomplete URL substring
 * sanitization — and while this is a build-time assertion about a file rather
 * than a security check on a request, the complaint is right about the method:
 * a URL is not something to reason about with substrings, and `includes` would
 * be satisfied by an origin that merely APPEARED somewhere in the file. Reading
 * the exported value back and comparing it EXACTLY is both stricter and says
 * what it means: after this, `origin.js` exports the origin this build was
 * given, or the build failed.
 */
const originModule = join(dist, 'origin.js');
const compiled = await readFile(originModule, 'utf8');
await writeFile(originModule, compiled.replace(DEFAULT_ORIGIN, origin));

const written = /PACKAGED_VAULT_ORIGIN = '([^']*)'/.exec(await readFile(originModule, 'utf8'))?.[1];
if (written !== origin) {
  throw new Error(`origin.js exports ${String(written)} after substitution, expected ${origin}`);
}

process.stdout.write(
  `vault-extension packaged for ${origin} (${String(statics.length)} static files)\n`,
);
