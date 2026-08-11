/**
 * Turn the vendored Public Suffix List into a module the extension can import.
 *
 * WHY A MODULE AND NOT THE FILE. `api.ts` is the extension's only network call
 * site (`test/fences.spec.ts`), and reading a packaged file at runtime means
 * `fetch(chrome.runtime.getURL(...))` — which would either breach that fence or
 * force it to be widened to allow fetches that "only" read local files. The
 * fence is worth more than the convenience, so the list becomes a plain import.
 *
 * THE TRANSFORMATION IS DELIBERATELY TRIVIAL: drop comment lines and blanks,
 * which is exactly what the PSL spec says a parser must do, and keep every rule
 * verbatim in order. `vendor/public-suffix-list.dat` stays byte-for-byte as
 * published — licence header included — and is the digest-pinned artifact;
 * `test/psl.spec.ts` regenerates from it and asserts the committed module
 * matches, so the two cannot drift.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

export function rulesFrom(source) {
  return source
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('//'));
}

export function moduleFor(rules, meta) {
  return `/**
 * GENERATED from vendor/public-suffix-list.dat by scripts/build-psl.mjs.
 * DO NOT EDIT. Refresh by re-running that script and reviewing the diff, which
 * is a deliberate act: this is a security parameter, not a dependency.
 *
 * Source: https://publicsuffix.org/list/public_suffix_list.dat
 * Licence: MPL-2.0 (the header travels with the vendored .dat)
 * Snapshot: ${meta.version}
 * Rules: ${String(rules.length)}
 */

/** One rule per line, in publication order. Split once at load. */
export const PUBLIC_SUFFIX_RULES = \`${rules.join('\n')}\`.split('\\n');
`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const source = readFileSync(join(root, 'vendor', 'public-suffix-list.dat'), 'utf8');
  const version = /^\/\/ VERSION: (.+)$/m.exec(source)?.[1] ?? 'unknown';
  const rules = rulesFrom(source);
  if (rules.length < 5000)
    throw new Error(`only ${rules.length} rules — refusing to write a truncated list`);
  // `OUT_FILE` exists for `test/psl.spec.ts`, which regenerates into a temp
  // path and compares — the `build-package.mjs` / `OUT_DIR` precedent. Writing
  // over the committed module from a test would make the drift check pass by
  // erasing the drift.
  writeFileSync(
    process.env.OUT_FILE ?? join(root, 'src', 'psl-data.ts'),
    moduleFor(rules, { version }),
  );
  process.stdout.write(`psl-data.ts: ${rules.length} rules from ${version}\n`);
}
