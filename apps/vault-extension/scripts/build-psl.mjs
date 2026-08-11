/**
 * Turn the vendored Public Suffix List into a module the extension can import.
 *
 * WHY A MODULE AND NOT THE FILE. `api.ts` is the extension's only network call
 * site (`test/fences.spec.ts`), and reading a packaged file at runtime means
 * `fetch(chrome.runtime.getURL(...))` — which would either breach that fence or
 * force it to be widened to allow fetches that "only" read local files. The
 * fence is worth more than the convenience, so the list becomes a plain import.
 *
 * THE TRANSFORMATION IS ALMOST TRIVIAL: drop comment lines and blanks, which is
 * exactly what the PSL spec says a parser must do, keep every rule in order —
 * and convert each to its A-LABEL form (see below). `vendor/public-suffix-list.dat`
 * stays byte-for-byte as published — licence header included — and is the
 * digest-pinned artifact; `test/psl.spec.ts` regenerates from it and asserts the
 * committed module matches, so the two cannot drift.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { domainToASCII, fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

/**
 * A-LABELS, BECAUSE THAT IS THE ONLY FORM A HOST EVER ARRIVES IN.
 *
 * The published list writes internationalised rules as U-labels (`公司.cn`)
 * while `URL.hostname` applies IDNA and returns the A-label
 * (`a.公司.cn` → `a.xn--55qx5d.cn`). `labelsMatch` compares raw strings, so a
 * U-label rule is one that can never match: 459 of the 10,239 rules were absent
 * from the algorithm entirely, the longest match fell back to the bare TLD, and
 * every registrant under those registries collapsed onto ONE registrable
 * domain — so `matchOrigin` answered `match` for two different registrants and
 * would have offered a credential on somebody else's site.
 *
 * CONVERTED HERE rather than at lookup, for three reasons: the vendored `.dat`
 * stays exactly as published and remains the thing the digest pins; the runtime
 * comparison stays a plain string compare with no IDNA in the hot path; and
 * this package has no runtime dependencies, so a browser-side implementation
 * would mean either a dependency or `new URL()` per rule at every load.
 *
 * The `!` and `*.` markers are NOT part of the domain and are stripped before
 * conversion. Measured against this snapshot: no rule combines a marker with a
 * non-ASCII label, and every wildcard and exception marker is leftmost — so
 * that handling is defence against a future refresh rather than something the
 * current list exercises. Conversion is also a verified no-op on all 9,780
 * ASCII rules, which is what keeps the regenerated diff to exactly the lines
 * that had to change.
 */
export function toALabels(rule) {
  const exception = rule.startsWith('!');
  const body = exception ? rule.slice(1) : rule;
  const wildcard = body.startsWith('*.');
  const domain = wildcard ? body.slice(2) : body;

  const ascii = domainToASCII(domain);
  if (ascii === '') {
    // Refuse rather than emit a rule that silently matches nothing — which is
    // the exact failure this conversion exists to end.
    throw new Error(`rule ${JSON.stringify(rule)} has no A-label form`);
  }
  return `${exception ? '!' : ''}${wildcard ? '*.' : ''}${ascii}`;
}

export function rulesFrom(source) {
  return source
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('//'))
    .map(toALabels);
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
